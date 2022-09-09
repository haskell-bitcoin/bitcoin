{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
--Module      : Haskoin.Transaction.Partial
--Copyright   : No rights reserved
--License     : MIT
--Maintainer  : matt@bitnomial.com
--Stability   : experimental
--Portability : POSIX
--
--Code related to PSBT parsing and serialization.
module Haskoin.Transaction.Partial (
    -- * Partially-Signed Transactions
    PartiallySignedTransaction (..),
    Input (..),
    Output (..),
    UnknownMap (..),
    Key (..),
    merge,
    mergeMany,
    mergeInput,
    mergeOutput,
    complete,
    finalTransaction,
    emptyPSBT,
    emptyInput,
    emptyOutput,

    -- ** Signing
    PsbtSigner,
    getSignerKey,
    secKeySigner,
    xPrvSigner,
    signPSBT,
) where

import Control.Applicative ((<|>))
import Control.DeepSeq
import Control.Monad (foldM, guard, replicateM, void)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Bytes.Get (runGetS)
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (Serial (..))
import Data.Either (fromRight)
import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HM
import qualified Data.HashMap.Strict as HashMap
import Data.Hashable (Hashable)
import Data.List (foldl')
import Data.Maybe (fromMaybe, isJust)
import GHC.Generics (Generic)
import GHC.Word (Word32, Word8)
import Haskoin.Address (Address (..), pubKeyAddr)
import Haskoin.Crypto (SecKey, derivePubKey)
import Haskoin.Data (Network)
import Haskoin.Keys (
    DerivPath,
    DerivPathI (Deriv),
    Fingerprint,
    KeyIndex,
    PubKeyI,
    SecKeyI (SecKeyI),
    XPrvKey,
    derivePath,
    deriveXPubKey,
    listToPath,
    pathToList,
    pubKeyCompressed,
    pubKeyPoint,
    xPrvKey,
    xPubFP,
 )
import Haskoin.Network (
    VarInt (..),
    VarString (..),
    putVarInt,
 )
import Haskoin.Script (
    Script (..),
    ScriptOp (..),
    ScriptOutput (..),
    SigHash,
    decodeOutput,
    decodeOutputBS,
    encodeOutputBS,
    encodeTxSig,
    isPayScriptHash,
    opPushData,
    sigHashAll,
    toP2SH,
    toP2WSH,
 )
import Haskoin.Transaction.Builder (SigInput (..), makeSignature)
import Haskoin.Transaction.Common (
    Tx (..),
    TxOut,
    WitnessStack,
    outPointIndex,
    outValue,
    prevOutput,
    scriptInput,
    scriptOutput,
 )
import Haskoin.Transaction.Segwit (isSegwit)
import Haskoin.Util (eitherToMaybe)


-- | PSBT data type as specified in
-- [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki).
-- This contains an unsigned transaction, inputs and outputs, and unspecified
-- extra data. There is one input per input in the unsigned transaction, and one
-- output per output in the unsigned transaction. The inputs and outputs in the
-- 'PartiallySignedTransaction' line up by index with the inputs and outputs in
-- the unsigned transaction.
data PartiallySignedTransaction = PartiallySignedTransaction
    { unsignedTransaction :: Tx
    , globalUnknown :: UnknownMap
    , inputs :: [Input]
    , outputs :: [Output]
    }
    deriving (Show, Eq, Generic)


instance NFData PartiallySignedTransaction


-- | Inputs contain all of the data needed to sign a transaction and all of the
-- resulting signature data after signing.
data Input = Input
    { nonWitnessUtxo :: Maybe Tx
    , witnessUtxo :: Maybe TxOut
    , partialSigs :: HashMap PubKeyI ByteString
    , sigHashType :: Maybe SigHash
    , inputRedeemScript :: Maybe Script
    , inputWitnessScript :: Maybe Script
    , inputHDKeypaths :: HashMap PubKeyI (Fingerprint, [KeyIndex])
    , finalScriptSig :: Maybe Script
    , finalScriptWitness :: Maybe WitnessStack
    , inputUnknown :: UnknownMap
    }
    deriving (Show, Eq, Generic)


instance NFData Input


-- | Outputs can contain information needed to spend the output at a later date.
data Output = Output
    { outputRedeemScript :: Maybe Script
    , outputWitnessScript :: Maybe Script
    , outputHDKeypaths :: HashMap PubKeyI (Fingerprint, [KeyIndex])
    , outputUnknown :: UnknownMap
    }
    deriving (Show, Eq, Generic)


instance NFData Output


-- | A map of raw PSBT keys to byte strings for extra data. The 'keyType' field
-- cannot overlap with any of the reserved 'keyType' fields specified in the
-- PSBT specification.
newtype UnknownMap = UnknownMap {unknownMap :: HashMap Key ByteString}
    deriving (Show, Eq, Semigroup, Monoid, Generic)


instance NFData UnknownMap


-- | Raw keys for the map type used in PSBTs.
data Key = Key
    { keyType :: Word8
    , key :: ByteString
    }
    deriving (Show, Eq, Generic)


instance NFData Key


instance Hashable Key


-- | Take two 'PartiallySignedTransaction's and merge them. The
-- 'unsignedTransaction' field in both must be the same.
merge ::
    PartiallySignedTransaction ->
    PartiallySignedTransaction ->
    Maybe PartiallySignedTransaction
merge psbt1 psbt2
    | unsignedTransaction psbt1 == unsignedTransaction psbt2 =
        Just $
            psbt1
                { globalUnknown = globalUnknown psbt1 <> globalUnknown psbt2
                , inputs = zipWith mergeInput (inputs psbt1) (inputs psbt2)
                , outputs = zipWith mergeOutput (outputs psbt1) (outputs psbt2)
                }
merge _ _ = Nothing


-- | A version of 'merge' for a collection of PSBTs.
--
-- @since 0.21.0
mergeMany :: [PartiallySignedTransaction] -> Maybe PartiallySignedTransaction
mergeMany (psbt : psbts) = foldM merge psbt psbts
mergeMany _ = Nothing


mergeInput :: Input -> Input -> Input
mergeInput a b =
    Input
        { nonWitnessUtxo =
            if isJust witUtx
                then Nothing
                else nonWitnessUtxo a <|> nonWitnessUtxo b
        , witnessUtxo =
            witUtx
        , sigHashType =
            sigHashType a <|> sigHashType b
        , partialSigs =
            partialSigs a <> partialSigs b
        , inputHDKeypaths =
            inputHDKeypaths a <> inputHDKeypaths b
        , inputUnknown =
            inputUnknown a <> inputUnknown b
        , inputRedeemScript =
            inputRedeemScript a <|> inputRedeemScript b
        , inputWitnessScript =
            inputWitnessScript a <|> inputWitnessScript b
        , finalScriptSig =
            finalScriptSig a <|> finalScriptSig b
        , finalScriptWitness =
            finalScriptWitness a <|> finalScriptWitness b
        }
    where
        witUtx = witnessUtxo a <|> witnessUtxo b


mergeOutput :: Output -> Output -> Output
mergeOutput a b =
    Output
        { outputRedeemScript =
            outputRedeemScript a <|> outputRedeemScript b
        , outputWitnessScript =
            outputWitnessScript a <|> outputWitnessScript b
        , outputHDKeypaths =
            outputHDKeypaths a <> outputHDKeypaths b
        , outputUnknown =
            outputUnknown a <> outputUnknown b
        }


-- | A abstraction which covers varying key configurations.  Use the 'Semigroup'
-- instance to create signers for sets of keys: `signerA <> signerB` can sign
-- anything for which `signerA` or `signerB` could sign.
--
-- @since 0.21@
newtype PsbtSigner = PsbtSigner
    { unPsbtSigner ::
        PubKeyI ->
        Maybe (Fingerprint, DerivPath) ->
        Maybe SecKey
    }


instance Semigroup PsbtSigner where
    PsbtSigner signer1 <> PsbtSigner signer2 =
        PsbtSigner $ \pubKey origin ->
            signer1 pubKey origin <|> signer2 pubKey origin


instance Monoid PsbtSigner where
    mempty = PsbtSigner $ \_ _ -> Nothing


-- | Fetch the secret key for the given 'PubKeyI' if possible.
--
-- @since 0.21@
getSignerKey :: PsbtSigner -> PubKeyI -> Maybe (Fingerprint, DerivPath) -> Maybe SecKey
getSignerKey = unPsbtSigner


-- | This signer can sign for one key.
--
-- @since 0.21@
secKeySigner :: SecKey -> PsbtSigner
secKeySigner theSecKey = PsbtSigner signer
    where
        signer requiredKey _
            | pubKeyPoint requiredKey == derivePubKey theSecKey = Just theSecKey
            | otherwise = Nothing


-- | This signer can sign with any child key, provided that derivation information is present.
--
-- @since 0.21@
xPrvSigner ::
    XPrvKey ->
    -- | Origin data, if the input key is explicitly a child key
    Maybe (Fingerprint, DerivPath) ->
    PsbtSigner
xPrvSigner xprv origin = PsbtSigner signer
    where
        signer pubKey (Just hdData)
            | result@(Just theSecKey) <- maybe noOrigin onOrigin origin hdData
              , pubKeyPoint pubKey == derivePubKey theSecKey =
                result
        signer _ _ = Nothing

        noOrigin (fp, path)
            | thisFP == fp = Just $ deriveSecKey path
            | otherwise = Nothing

        onOrigin (originFP, originPath) (fp, path)
            | thisFP == fp = Just $ deriveSecKey path
            | originFP == fp =
                deriveSecKey <$> adjustPath (pathToList originPath) (pathToList path)
            | otherwise = Nothing

        deriveSecKey path = xPrvKey $ derivePath path xprv

        thisFP = xPubFP $ deriveXPubKey xprv

        -- The origin path should be a prefix of the target path if we match the
        -- origin fingerprint.  We need to remove this prefix.
        adjustPath :: [KeyIndex] -> [KeyIndex] -> Maybe DerivPath
        adjustPath (originIx : originTail) (thisIx : thisTail)
            | originIx == thisIx = adjustPath originTail thisTail
            | otherwise = Nothing
        adjustPath [] thePath = Just $ listToPath thePath
        adjustPath _ _ = Nothing


-- | Update a PSBT with signatures when possible.  This function uses
-- 'inputHDKeypaths' in order to calculate secret keys.
--
-- @since 0.21@
signPSBT ::
    Network ->
    PsbtSigner ->
    PartiallySignedTransaction ->
    PartiallySignedTransaction
signPSBT net signer psbt =
    psbt
        { inputs = addSigsForInput net signer tx <$> zip [0 :: Int ..] (inputs psbt)
        }
    where
        tx = unsignedTransaction psbt


addSigsForInput :: Network -> PsbtSigner -> Tx -> (Int, Input) -> Input
addSigsForInput net signer tx (ix, input) =
    maybe input (onPrevTxOut net signer tx ix input) $
        Left <$> nonWitnessUtxo input <|> Right <$> witnessUtxo input


onPrevTxOut ::
    Network ->
    PsbtSigner ->
    Tx ->
    Int ->
    Input ->
    Either Tx TxOut ->
    Input
onPrevTxOut net signer tx ix input prevTxData =
    input
        { partialSigs = newSigs <> partialSigs input
        }
    where
        newSigs = HM.mapWithKey sigForInput sigKeys
        sigForInput thePubKey theSecKey =
            encodeTxSig . makeSignature net tx ix theSigInput $
                SecKeyI theSecKey (pubKeyCompressed thePubKey)

        theSigInput =
            SigInput
                { -- Must be the segwit input script for segwit spends (even nested)
                  sigInputScript = fromMaybe theInputScript segwitInput
                , sigInputValue = outValue prevTxOut
                , sigInputOP = thePrevOutPoint
                , sigInputSH = fromMaybe sigHashAll $ sigHashType input
                , -- Must be the witness script for segwit spends (even nested)
                  sigInputRedeem = theWitnessScript <|> theRedeemScript
                }

        prevTxOut = either ((!! (fromIntegral . outPointIndex) thePrevOutPoint) . txOut) id prevTxData
        thePrevOutPoint = prevOutput $ txIn tx !! ix

        segwitInput = justWhen isSegwit theInputScript <|> (justWhen isSegwit =<< theRedeemScript)

        theInputScript = fromRight inputScriptErr $ (decodeOutputBS . scriptOutput) prevTxOut
        inputScriptErr = error "addSigsForInput: Unable to decode input script"

        theRedeemScript = case decodeOutput <$> inputRedeemScript input of
            Just (Right script) -> Just script
            Just Left{} -> error "addSigsForInput: Unable to decode redeem script"
            _ -> Nothing

        theWitnessScript = case decodeOutput <$> inputWitnessScript input of
            Just (Right script) -> Just script
            Just Left{} -> error "addSigsForInput: Unable to decode witness script"
            _ -> Nothing

        sigKeys = HM.mapMaybeWithKey getSignerKey $ inputHDKeypaths input
        getSignerKey pubKey (fp, ixs) = unPsbtSigner signer pubKey $ Just (fp, listToPath ixs)


-- | Take partial signatures from all of the 'Input's and finalize the signature.
complete ::
    PartiallySignedTransaction ->
    PartiallySignedTransaction
complete psbt =
    psbt
        { inputs =
            map
                (completeInput . analyzeInputs)
                (indexed $ inputs psbt)
        }
    where
        analyzeInputs (i, input) =
            (,)
                (outputScript =<< witnessUtxo input <|> nonWitScript)
                input
            where
                nonWitScript = getPrevOut i =<< nonWitnessUtxo input

        getPrevOut i tx =
            (txOut tx !!?)
                . fromIntegral
                . outPointIndex
                . prevOutput
                =<< txIn (unsignedTransaction psbt) !!? i
        xs !!? i = lookup i $ indexed xs

        outputScript = eitherToMaybe . decodeOutputBS . scriptOutput

        completeInput (Nothing, input) = input
        completeInput (Just script, input) = pruneInputFields $ completeSig input script

        -- If we have final scripts, we can get rid of data for signing following
        -- the Bitcoin Core implementation.
        pruneInputFields input
            | isJust (finalScriptSig input) || isJust (finalScriptWitness input) =
                input
                    { partialSigs = mempty
                    , inputHDKeypaths = mempty
                    , inputRedeemScript = Nothing
                    , inputWitnessScript = Nothing
                    , sigHashType = Nothing
                    }
            | otherwise = input

        indexed :: [a] -> [(Word32, a)]
        indexed = zip [0 ..]


completeSig :: Input -> ScriptOutput -> Input
completeSig input (PayPK k) =
    input
        { finalScriptSig =
            eitherToMaybe . runGetS deserialize
                =<< HashMap.lookup k (partialSigs input)
        }
completeSig input (PayPKHash h)
    | [(k, sig)] <- HashMap.toList (partialSigs input)
      , PubKeyAddress h == pubKeyAddr k =
        input
            { finalScriptSig =
                Just $
                    Script
                        [ opPushData sig
                        , opPushData (runPutS (serialize k))
                        ]
            }
completeSig input (PayMulSig pubKeys m)
    | length sigs >= m =
        input{finalScriptSig = Just finalSig}
    where
        sigs = collectSigs m pubKeys input
        finalSig = Script $ OP_0 : map opPushData sigs
completeSig input (PayScriptHash h)
    | Just rdmScript <- inputRedeemScript input
      , PayScriptHash h == toP2SH rdmScript
      , Right decodedScript <- decodeOutput rdmScript
      , not (isPayScriptHash decodedScript) =
        pushScript rdmScript $ completeSig input decodedScript
    where
        pushScript rdmScript updatedInput =
            updatedInput
                { finalScriptSig =
                    Just $
                        fromMaybe (Script mempty) (finalScriptSig updatedInput)
                            `scriptAppend` serializedRedeemScript rdmScript
                }
        scriptAppend (Script script1) (Script script2) = Script $ script1 <> script2
completeSig input (PayWitnessPKHash h)
    | [(k, sig)] <- HashMap.toList (partialSigs input)
      , PubKeyAddress h == pubKeyAddr k =
        input{finalScriptWitness = Just [sig, runPutS $ serialize k]}
completeSig input (PayWitnessScriptHash h)
    | Just witScript <- inputWitnessScript input
      , PayWitnessScriptHash h == toP2WSH witScript
      , Right decodedScript <- decodeOutput witScript =
        completeWitnessSig input decodedScript
completeSig input _ = input


serializedRedeemScript :: Script -> Script
serializedRedeemScript = Script . pure . opPushData . runPutS . serialize


completeWitnessSig :: Input -> ScriptOutput -> Input
completeWitnessSig input script@(PayMulSig pubKeys m)
    | length sigs >= m =
        input{finalScriptWitness = Just finalWit}
    where
        sigs = collectSigs m pubKeys input
        finalWit = mempty : sigs <> [encodeOutputBS script]
completeWitnessSig input _ = input


collectSigs :: Int -> [PubKeyI] -> Input -> [ByteString]
collectSigs m pubKeys input =
    take m . reverse $ foldl' lookupKey [] pubKeys
    where
        lookupKey sigs key =
            maybe sigs (: sigs) $
                HashMap.lookup key (partialSigs input)


-- | Take a finalized 'PartiallySignedTransaction' and produce the signed final
-- transaction. You may need to call 'complete' on the
-- 'PartiallySignedTransaction' before producing the final transaction.
finalTransaction :: PartiallySignedTransaction -> Tx
finalTransaction psbt =
    setInputs
        . foldl' finalizeInput ([], [])
        $ zip (txIn tx) (inputs psbt)
    where
        tx = unsignedTransaction psbt
        hasWitness =
            any
                (isJust . finalScriptWitness)
                (inputs psbt)
        setInputs (ins, witData) =
            tx
                { txIn = reverse ins
                , txWitness = if hasWitness then reverse witData else []
                }
        finalizeInput (ins, witData) (txInput, psbtInput) =
            ( txInput{scriptInput = maybe mempty (runPutS . serialize) $ finalScriptSig psbtInput} : ins
            , fromMaybe [] (finalScriptWitness psbtInput) : witData
            )


-- | Take an unsigned transaction and produce an empty
-- 'PartiallySignedTransaction'
emptyPSBT :: Tx -> PartiallySignedTransaction
emptyPSBT tx =
    PartiallySignedTransaction
        { unsignedTransaction = tx
        , globalUnknown = mempty
        , inputs = replicate (length (txIn tx)) emptyInput
        , outputs = replicate (length (txOut tx)) emptyOutput
        }


emptyInput :: Input
emptyInput =
    Input
        Nothing
        Nothing
        HashMap.empty
        Nothing
        Nothing
        Nothing
        HashMap.empty
        Nothing
        Nothing
        (UnknownMap HashMap.empty)


emptyOutput :: Output
emptyOutput = Output Nothing Nothing HashMap.empty (UnknownMap HashMap.empty)


data InputType
    = InNonWitnessUtxo
    | InWitnessUtxo
    | InPartialSig
    | InSigHashType
    | InRedeemScript
    | InWitnessScript
    | InBIP32Derivation
    | InFinalScriptSig
    | InFinalScriptWitness
    deriving (Show, Eq, Enum, Bounded, Generic)


instance NFData InputType


data OutputType
    = OutRedeemScript
    | OutWitnessScript
    | OutBIP32Derivation
    deriving (Show, Eq, Enum, Bounded, Generic)


instance NFData OutputType


newtype PSBTHDPath = PSBTHDPath {unPSBTHDPath :: (Fingerprint, [KeyIndex])}
    deriving (Show, Eq, Generic)


instance NFData PSBTHDPath


enumWord8 :: Enum a => a -> Word8
enumWord8 = fromIntegral . fromEnum


word8Enum :: forall a. (Bounded a, Enum a) => Word8 -> Either Word8 a
word8Enum n | n <= enumWord8 (maxBound :: a) = Right . toEnum $ fromIntegral n
word8Enum n = Left n


whenJust :: Monad m => (a -> m ()) -> Maybe a -> m ()
whenJust = maybe (return ())


justWhen :: (a -> Bool) -> a -> Maybe a
justWhen test x = if test x then Just x else Nothing
