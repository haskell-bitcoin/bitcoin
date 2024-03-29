{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Stability   : experimental
-- Portability : POSIX
--
-- Code related to PSBT parsing and serialization.
module Bitcoin.Transaction.Partial (
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

import Bitcoin.Address (Address (..), pubKeyAddr)
import Bitcoin.Crypto (SecKey, derivePubKey)
import Bitcoin.Data (Network)
import Bitcoin.Keys (
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
import Bitcoin.Network (
    VarInt (..),
    VarString (..),
    putVarInt,
 )
import Bitcoin.Script (
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
import Bitcoin.Transaction.Builder (SigInput (..), makeSignature)
import Bitcoin.Transaction.Common (
    Tx (..),
    TxOut,
    WitnessStack,
    outPointIndex,
    outValue,
    prevOutput,
    scriptInput,
    scriptOutput,
 )
import Bitcoin.Transaction.Segwit (isSegwit)
import Bitcoin.Util (eitherToMaybe)
import qualified Bitcoin.Util as U
import Control.Applicative ((<|>))
import Control.DeepSeq
import Control.Monad (foldM, guard, replicateM, void)
import Data.Binary (Binary (..))
import Data.Binary.Get (Get, getByteString, getWord32le, getWord8, isolate, lookAhead)
import Data.Binary.Put (Put, putByteString, putLazyByteString, putWord32le, putWord8, runPut)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Either (fromRight)
import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HM
import qualified Data.HashMap.Strict as HashMap
import Data.Hashable (Hashable)
import Data.List (foldl')
import Data.Maybe (fromMaybe, isJust)
import GHC.Generics (Generic)
import GHC.Word (Word32, Word8)


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
getSignerKey :: PsbtSigner -> PubKeyI -> Maybe (Fingerprint, DerivPath) -> Maybe SecKey
getSignerKey = unPsbtSigner


-- | This signer can sign for one key.
secKeySigner :: SecKey -> PsbtSigner
secKeySigner theSecKey = PsbtSigner signer
  where
    signer requiredKey _
        | pubKeyPoint requiredKey == derivePubKey theSecKey = Just theSecKey
        | otherwise = Nothing


-- | This signer can sign with any child key, provided that derivation information is present.
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
            eitherToMaybe . U.decode . BSL.fromStrict
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
                        , opPushData $ U.encodeS k
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
        input{finalScriptWitness = Just [sig, U.encodeS k]}
completeSig input (PayWitnessScriptHash h)
    | Just witScript <- inputWitnessScript input
    , PayWitnessScriptHash h == toP2WSH witScript
    , Right decodedScript <- decodeOutput witScript =
        completeWitnessSig input decodedScript
completeSig input _ = input


serializedRedeemScript :: Script -> Script
serializedRedeemScript = Script . pure . opPushData . U.encodeS


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
        ( txInput{scriptInput = maybe mempty U.encodeS $ finalScriptSig psbtInput} : ins
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


instance Binary PartiallySignedTransaction where
    get = do
        magic <- getByteString 4
        guard $ magic == "psbt"
        headerSep <- getWord8
        guard $ headerSep == 0xff

        keySize <- getWord8
        guard $ keySize == 1
        globalUnsignedTxType <- getWord8
        guard $ globalUnsignedTxType == 0x00
        unsignedTransaction <- getSizedBytes get
        guard $ all (BS.null . scriptInput) (txIn unsignedTransaction)
        guard $ null (txWitness unsignedTransaction)

        globalUnknown <- get
        globalEnd <- getWord8
        guard $ globalEnd == 0x00

        inputs <-
            replicateM
                (length (txIn unsignedTransaction))
                get
        outputs <-
            replicateM
                (length (txOut unsignedTransaction))
                get

        return
            PartiallySignedTransaction
                { unsignedTransaction
                , globalUnknown
                , inputs
                , outputs
                }


    put
        PartiallySignedTransaction
            { unsignedTransaction
            , globalUnknown
            , inputs
            , outputs
            } = do
            putByteString "psbt"
            putWord8 0xff -- Header separator
            putWord8 0x01 -- Key size
            putWord8 0x00 -- Unsigned Transaction type
            putSizedBytes $ put unsignedTransaction
            put globalUnknown
            putWord8 0x00 -- Global end
            mapM_ put inputs
            mapM_ put outputs


instance Binary Key where
    get = do
        VarInt keySize <- get
        guard $ keySize > 0
        t <- getWord8
        k <- getByteString (fromIntegral keySize - 1)
        return (Key t k)


    put (Key t k) = do
        putVarInt $ 1 + BS.length k
        putWord8 t
        putByteString k


instance Binary UnknownMap where
    get = go HashMap.empty
      where
        getItem m = do
            k <- get
            VarString v <- get
            go $ HashMap.insert k v m
        go m = do
            isEnd <- lookAhead getWord8
            if isEnd == 0x00
                then return (UnknownMap m)
                else getItem m


    put (UnknownMap m) =
        void $
            HashMap.traverseWithKey
                (\k v -> put k >> put (VarString v))
                m


instance Binary Input where
    get =
        getMap getInputItem setInputUnknown emptyInput
      where
        setInputUnknown f input =
            input
                { inputUnknown =
                    UnknownMap (f (unknownMap (inputUnknown input)))
                }


    put
        Input
            { nonWitnessUtxo
            , witnessUtxo
            , partialSigs
            , sigHashType
            , inputRedeemScript
            , inputWitnessScript
            , inputHDKeypaths
            , finalScriptSig
            , finalScriptWitness
            , inputUnknown
            } = do
            whenJust
                (putKeyValue InNonWitnessUtxo . put)
                nonWitnessUtxo
            whenJust
                (putKeyValue InWitnessUtxo . put)
                witnessUtxo
            putPartialSig partialSigs
            whenJust
                putSigHash
                sigHashType
            whenJust
                (putKeyValue InRedeemScript . put)
                inputRedeemScript
            whenJust
                (putKeyValue InWitnessScript . put)
                inputWitnessScript
            putHDPath InBIP32Derivation inputHDKeypaths
            whenJust
                (putKeyValue InFinalScriptSig . put)
                finalScriptSig
            whenJust
                (putKeyValue InFinalScriptWitness . putFinalScriptWitness)
                finalScriptWitness
            put inputUnknown
            putWord8 0x00
          where
            putPartialSig =
                putPubKeyMap put InPartialSig . fmap VarString
            putSigHash sigHash = do
                putKey InSigHashType
                putWord8 0x04
                putWord32le (fromIntegral sigHash)
            putFinalScriptWitness witnessStack = do
                put $ (VarInt . fromIntegral . length) witnessStack
                mapM_ (put . VarString) witnessStack


instance Binary Output where
    get = getMap getOutputItem setOutputUnknown emptyOutput
      where
        setOutputUnknown f output =
            output
                { outputUnknown =
                    UnknownMap (f (unknownMap (outputUnknown output)))
                }


    put
        Output
            { outputRedeemScript
            , outputWitnessScript
            , outputHDKeypaths
            , outputUnknown
            } = do
            whenJust
                (putKeyValue OutRedeemScript . put)
                outputRedeemScript
            whenJust
                (putKeyValue OutWitnessScript . put)
                outputWitnessScript
            putHDPath
                OutBIP32Derivation
                outputHDKeypaths
            put outputUnknown
            putWord8 0x00


putSizedBytes :: Put -> Put
putSizedBytes f = do
    putVarInt (BSL.length bs)
    putLazyByteString bs
  where
    bs = runPut f


getSizedBytes :: Get a -> Get a
getSizedBytes getItem = do
    n <- fromIntegral . getVarInt <$> get
    isolate n getItem


putKeyValue :: Enum t => t -> Put -> Put
putKeyValue t v = do
    putKey t
    putSizedBytes v


putKey :: Enum t => t -> Put
putKey t = do
    putVarInt (1 :: Word8)
    putWord8 (enumWord8 t)


getMap ::
    (Bounded t, Enum t) =>
    (Int -> a -> t -> Get a) ->
    ((HashMap Key ByteString -> HashMap Key ByteString) -> a -> a) ->
    a ->
    Get a
getMap getMapItem setUnknown = go
  where
    getItem keySize m (Right t) =
        getMapItem (fromIntegral keySize - 1) m t >>= go
    getItem keySize m (Left t) = do
        k <- getByteString (fromIntegral keySize - 1)
        VarString v <- get
        go $ setUnknown (HashMap.insert (Key t k) v) m
    go m = do
        keySize <- getVarInt <$> get
        if keySize == 0
            then return m
            else getItem keySize m . word8Enum =<< getWord8


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


getInputItem :: Int -> Input -> InputType -> Get Input
getInputItem 0 input@Input{nonWitnessUtxo = Nothing} InNonWitnessUtxo = do
    utxo <- getSizedBytes get
    return input{nonWitnessUtxo = Just utxo}
getInputItem 0 input@Input{witnessUtxo = Nothing} InWitnessUtxo = do
    utxo <- getSizedBytes get
    return input{witnessUtxo = Just utxo}
getInputItem keySize input InPartialSig = do
    (k, v) <- getPartialSig
    return
        input
            { partialSigs = HashMap.insert k v (partialSigs input)
            }
  where
    getPartialSig =
        (,)
            <$> isolate keySize get
            <*> (getVarString <$> get)
getInputItem 0 input@Input{sigHashType = Nothing} InSigHashType = do
    VarInt size <- get
    guard $ size == 0x04
    sigHash <- fromIntegral <$> getWord32le
    return $ input{sigHashType = Just sigHash}
getInputItem 0 input@Input{inputRedeemScript = Nothing} InRedeemScript = do
    script <- getSizedBytes get
    return $ input{inputRedeemScript = Just script}
getInputItem 0 input@Input{inputWitnessScript = Nothing} InWitnessScript = do
    script <- getSizedBytes get
    return $ input{inputWitnessScript = Just script}
getInputItem keySize input InBIP32Derivation = do
    (k, v) <- getHDPath keySize
    return
        input
            { inputHDKeypaths = HashMap.insert k v (inputHDKeypaths input)
            }
getInputItem 0 input@Input{finalScriptSig = Nothing} InFinalScriptSig = do
    script <- getSizedBytes get
    return $ input{finalScriptSig = Just script}
getInputItem 0 input@Input{finalScriptWitness = Nothing} InFinalScriptWitness = do
    scripts <- map getVarString <$> getVarIntList
    return $ input{finalScriptWitness = Just scripts}
  where
    getVarIntList = getSizedBytes $ do
        VarInt n <- get -- Item count
        replicateM (fromIntegral n) get
getInputItem keySize input inputType =
    fail $
        "Incorrect key size for input item or item already existed: "
            <> show (keySize, input, inputType)


getOutputItem :: Int -> Output -> OutputType -> Get Output
getOutputItem 0 output@Output{outputRedeemScript = Nothing} OutRedeemScript = do
    script <- getSizedBytes get
    return $ output{outputRedeemScript = Just script}
getOutputItem 0 output@Output{outputWitnessScript = Nothing} OutWitnessScript = do
    script <- getSizedBytes get
    return $ output{outputWitnessScript = Just script}
getOutputItem keySize output OutBIP32Derivation = do
    (k, v) <- getHDPath keySize
    return $ output{outputHDKeypaths = HashMap.insert k v (outputHDKeypaths output)}
getOutputItem keySize output outputType =
    fail $
        "Incorrect key size for output item or item already existed: "
            <> show (keySize, output, outputType)


getHDPath :: Int -> Get (PubKeyI, (Fingerprint, [KeyIndex]))
getHDPath keySize =
    (,)
        <$> isolate keySize get
        <*> (unPSBTHDPath <$> get)


putHDPath :: Enum t => t -> HashMap PubKeyI (Fingerprint, [KeyIndex]) -> Put
putHDPath t = putPubKeyMap put t . fmap PSBTHDPath


newtype PSBTHDPath = PSBTHDPath {unPSBTHDPath :: (Fingerprint, [KeyIndex])}
    deriving (Show, Eq, Generic)


instance NFData PSBTHDPath


instance Binary PSBTHDPath where
    get = do
        VarInt valueSize <- get
        guard $ valueSize `mod` 4 == 0
        let numIndices = (fromIntegral valueSize - 4) `div` 4
        PSBTHDPath
            <$> isolate
                (fromIntegral valueSize)
                ((,) <$> get <*> getKeyIndexList numIndices)
      where
        getKeyIndexList n = replicateM n getWord32le


    put (PSBTHDPath (fp, kis)) = do
        putVarInt (BSL.length bs)
        putLazyByteString bs
      where
        bs = runPut $ put fp >> mapM_ putWord32le kis


putPubKeyMap :: Enum t => (a -> Put) -> t -> HashMap PubKeyI a -> Put
putPubKeyMap f t =
    void . HashMap.traverseWithKey putItem
  where
    putItem k v = do
        put $ Key (enumWord8 t) $ U.encodeS k
        f v


enumWord8 :: Enum a => a -> Word8
enumWord8 = fromIntegral . fromEnum


word8Enum :: forall a. (Bounded a, Enum a) => Word8 -> Either Word8 a
word8Enum n | n <= enumWord8 (maxBound :: a) = Right . toEnum $ fromIntegral n
word8Enum n = Left n


whenJust :: Monad m => (a -> m ()) -> Maybe a -> m ()
whenJust = maybe (return ())


justWhen :: (a -> Bool) -> a -> Maybe a
justWhen test x = if test x then Just x else Nothing
