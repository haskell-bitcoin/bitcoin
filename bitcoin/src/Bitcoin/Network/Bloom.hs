{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}

-- |
-- Stability   : experimental
-- Portability : POSIX
--
-- Bloom filters are used to reduce data transfer when synchronizing thin cients.
-- When bloom filters are used a client will obtain filtered blocks that only
-- contain transactions that pass the bloom filter. Transactions announced via inv
-- messages also pass the filter.
module Bitcoin.Network.Bloom (
    -- * Bloom Filters
    BloomFlags (..),
    BloomFilter (..),
    FilterLoad (..),
    FilterAdd (..),
    bloomCreate,
    bloomInsert,
    bloomContains,
    isBloomValid,
    isBloomEmpty,
    isBloomFull,
    acceptsFilters,
    bloomRelevantUpdate,
) where

import Bitcoin.Network.Common (VarInt (VarInt), putVarInt)
import Bitcoin.Script.Standard (
    ScriptOutput (..),
    decodeOutputBS,
    isPayMulSig,
    isPayPK,
 )
import Bitcoin.Transaction.Common (
    OutPoint (..),
    Tx (txOut),
    TxOut (scriptOutput),
    txHash,
 )
import qualified Bitcoin.Util as U
import Control.DeepSeq (NFData)
import Control.Monad (replicateM)
import Data.Binary (Binary (..))
import Data.Binary.Get (getByteString, getWord32le, getWord8)
import Data.Binary.Put (putByteString, putWord32le, putWord8)
import Data.Bits (Bits (shiftL, shiftR, (.&.), (.|.)))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.Foldable as F
import Data.Hash.Murmur (murmur3)
import Data.List (foldl')
import qualified Data.Sequence as S
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)


-- | 20,000 items with fp rate < 0.1% or 10,000 items and <0.0001%
maxBloomSize :: Int
maxBloomSize = 36000


maxHashFuncs :: Word32
maxHashFuncs = 50


ln2Squared :: Double
ln2Squared = 0.4804530139182014246671025263266649717305529515945455


ln2 :: Double
ln2 = 0.6931471805599453094172321214581765680755001343602552


bitMask :: [Word8]
bitMask = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]


-- | The bloom flags are used to tell the remote peer how to auto-update
-- the provided bloom filter.
data BloomFlags
    = -- | never update
      BloomUpdateNone
    | -- | auto-update on all outputs
      BloomUpdateAll
    | -- | auto-update on pay-to-pubkey or pay-to-multisig (default)
      BloomUpdateP2PubKeyOnly
    deriving (Eq, Show, Read, Generic, NFData)


instance Binary BloomFlags where
    get = go =<< getWord8
      where
        go 0 = return BloomUpdateNone
        go 1 = return BloomUpdateAll
        go 2 = return BloomUpdateP2PubKeyOnly
        go _ = fail "BloomFlags get: Invalid bloom flag"


    put f = putWord8 $ case f of
        BloomUpdateNone -> 0
        BloomUpdateAll -> 1
        BloomUpdateP2PubKeyOnly -> 2


-- | A bloom filter is a probabilistic data structure that SPV clients send to
-- other peers to filter the set of transactions received from them. Bloom
-- filters can have false positives but not false negatives. Some transactions
-- that pass the filter may not be relevant to the receiving peer. By
-- controlling the false positive rate, SPV nodes can trade off bandwidth
-- versus privacy.
data BloomFilter = BloomFilter
    { bloomData :: !(S.Seq Word8)
    -- ^ bloom filter data
    , bloomHashFuncs :: !Word32
    -- ^ number of hash functions for this filter
    , bloomTweak :: !Word32
    -- ^ hash function random nonce
    , bloomFlags :: !BloomFlags
    -- ^ bloom filter auto-update flags
    }
    deriving (Eq, Show, Read, Generic, NFData)


instance Binary BloomFilter where
    get =
        BloomFilter
            <$> (S.fromList <$> (readDat =<< get))
            <*> getWord32le
            <*> getWord32le
            <*> get
      where
        readDat (VarInt len) = replicateM (fromIntegral len) getWord8


    put (BloomFilter dat hashFuncs tweak flags) = do
        putVarInt $ S.length dat
        mapM_ putWord8 $ F.toList dat
        putWord32le hashFuncs
        putWord32le tweak
        put flags


-- | Set a new bloom filter on the peer connection.
newtype FilterLoad = FilterLoad {filterLoadBloomFilter :: BloomFilter}
    deriving (Eq, Show, Read, Generic, NFData, Binary)


-- | Add the given data element to the connections current filter without
-- requiring a completely new one to be set.
newtype FilterAdd = FilterAdd {getFilterData :: ByteString}
    deriving (Eq, Show, Read, Generic, NFData)


instance Binary FilterAdd where
    get = do
        (VarInt len) <- get
        FilterAdd <$> getByteString (fromIntegral len)


    put (FilterAdd bs) = do
        putVarInt $ BS.length bs
        putByteString bs


-- | Build a bloom filter that will provide the given false positive rate when
-- the given number of elements have been inserted.
bloomCreate ::
    -- | number of elements
    Int ->
    -- | false positive rate
    Double ->
    -- | random nonce (tweak) for the hash function
    Word32 ->
    -- | bloom filter flags
    BloomFlags ->
    -- | bloom filter
    BloomFilter
bloomCreate numElem fpRate =
    BloomFilter (S.replicate bloomSize 0) numHashF
  where
    -- Bloom filter size in bytes
    bloomSize = truncate $ min a b / 8
    -- Suggested size in bits
    a = -1 / ln2Squared * fromIntegral numElem * log fpRate
    -- Maximum size in bits
    b = fromIntegral $ maxBloomSize * 8
    numHashF = truncate $ min c (fromIntegral maxHashFuncs)
    -- Suggested number of hash functions
    c = fromIntegral bloomSize * 8 / fromIntegral numElem * ln2


bloomHash :: BloomFilter -> Word32 -> ByteString -> Word32
bloomHash bfilter hashNum bs =
    murmur3 seed bs `mod` (fromIntegral (S.length (bloomData bfilter)) * 8)
  where
    seed = hashNum * 0xfba4c795 + bloomTweak bfilter


-- | Insert arbitrary data into a bloom filter. Returns the new bloom filter
-- containing the new data.
bloomInsert ::
    -- | Original bloom filter
    BloomFilter ->
    -- | New data to insert
    ByteString ->
    -- | Bloom filter containing the new data
    BloomFilter
bloomInsert bfilter bs
    | isBloomFull bfilter = bfilter
    | otherwise = bfilter{bloomData = newData}
  where
    idxs = map (\i -> bloomHash bfilter i bs) [0 .. bloomHashFuncs bfilter - 1]
    upd s i =
        S.adjust
            (.|. bitMask !! fromIntegral (7 .&. i))
            (fromIntegral $ i `shiftR` 3)
            s
    newData = foldl upd (bloomData bfilter) idxs


-- | Tests if some arbitrary data matches the filter. This can be either because
-- the data was inserted into the filter or because it is a false positive.
bloomContains ::
    -- | Bloom filter
    BloomFilter ->
    -- | Data that will be checked against the given bloom filter
    ByteString ->
    -- | Returns True if the data matches the filter
    Bool
bloomContains bfilter bs
    | isBloomFull bfilter = True
    | isBloomEmpty bfilter = False
    | otherwise = all isSet idxs
  where
    s = bloomData bfilter
    idxs = map (\i -> bloomHash bfilter i bs) [0 .. bloomHashFuncs bfilter - 1]
    isSet i =
        S.index s (fromIntegral $ i `shiftR` 3)
            .&. (bitMask !! fromIntegral (7 .&. i))
            /= 0


-- | Checks if any of the outputs of a tx is in the current bloom filter.
-- If it is, add the txid and vout as an outpoint (i.e. so that
-- a future tx that spends the output won't be missed).
bloomRelevantUpdate ::
    -- | Bloom filter
    BloomFilter ->
    -- | Tx that may (or may not) have relevant outputs
    Tx ->
    -- | Returns an updated bloom filter adding relevant output
    Maybe BloomFilter
bloomRelevantUpdate bfilter tx
    | isBloomFull bfilter || isBloomEmpty bfilter = Nothing
    | bloomFlags bfilter == BloomUpdateNone = Nothing
    | not (null matchOuts) = Just $ foldl' addRelevant bfilter matchOuts
    | otherwise = Nothing
  where
    -- TxHash if we end up inserting an outpoint

    h = txHash tx
    -- Decode the scriptOutpus and add vOuts in case we make them outpoints
    decodedOutputScripts = traverse (decodeOutputBS . scriptOutput) $ txOut tx
    err = error "Error Decoding output script"
    idxOutputScripts = either (const err) (zip [0 ..]) decodedOutputScripts
    -- Check if any txOuts were contained in the bloom filter
    matchFilter =
        filter (\(_, op) -> bloomContains bfilter $ encodeScriptOut op)
    matchOuts = matchFilter idxOutputScripts
    addRelevant :: BloomFilter -> (Word32, ScriptOutput) -> BloomFilter
    addRelevant bf (id', scriptOut) =
        case (bloomFlags bfilter, scriptType) of
            -- We filtered out BloomUpdateNone so we insert any PayPk or PayMulSig

            (_, True) -> bloomInsert bf outpoint
            (BloomUpdateAll, _) -> bloomInsert bf outpoint
            _ -> error "Error Updating Bloom Filter with relevant outpoint"
      where
        outpoint = U.encodeS $ OutPoint{outPointHash = h, outPointIndex = id'}
        scriptType = (\s -> isPayPK s || isPayMulSig s) scriptOut
    -- Encodes a scriptOutput so it can be checked agains the Bloom Filter
    encodeScriptOut :: ScriptOutput -> ByteString
    encodeScriptOut (PayMulSig outputMuSig _) = U.encodeS outputMuSig
    encodeScriptOut (PayWitnessScriptHash scriptHash) = U.encodeS scriptHash
    encodeScriptOut (DataCarrier getOutputDat) = U.encodeS getOutputDat
    encodeScriptOut outputHash = (U.encodeS . getOutputHash) outputHash


-- | Returns True if the filter is empty (all bytes set to 0x00)
isBloomEmpty :: BloomFilter -> Bool
isBloomEmpty bfilter = all (== 0x00) $ F.toList $ bloomData bfilter


-- | Returns True if the filter is full (all bytes set to 0xff)
isBloomFull :: BloomFilter -> Bool
isBloomFull bfilter = all (== 0xff) $ F.toList $ bloomData bfilter


-- | Tests if a given bloom filter is valid.
isBloomValid ::
    -- | Bloom filter to test
    BloomFilter ->
    -- | True if the given filter is valid
    Bool
isBloomValid bfilter =
    S.length (bloomData bfilter) <= maxBloomSize
        && bloomHashFuncs bfilter <= maxHashFuncs


-- | Does the peer with these version services accept bloom filters?
acceptsFilters :: Word64 -> Bool
acceptsFilters srv = srv .&. (1 `shiftL` 2) /= 0
