{-# LANGUAGE OverloadedStrings #-}
module Network.Haskoin.Address.CashAddr
    ( CashPrefix
    , CashVersion
    , CashAddr
    , Cash32
    , cashAddrDecode
    , cashAddrEncode
    , cash32decode
    , cash32encode
    ) where

import           Control.Monad
import           Control.Monad.State.Strict
import           Data.Bits
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import qualified Data.ByteString.Char8      as C
import           Data.Char
import           Data.List
import           Data.Maybe
import           Data.Word
import           Debug.Trace
import           Network.Haskoin.Constants
import           Network.Haskoin.Util

-- | 'CashAddr' prefix, usually shown before the colon in addresses, but sometimes
-- omitted. It is used in the checksum calculation to avoid parsing an address
-- from the wrong network.
type CashPrefix = ByteString

-- | 'CashAddr' version, until new address schemes appear it will be zero.
type CashVersion = Word8

-- | High level 'CashAddr' human-reabale string, with explicit or implicit prefix.
type CashAddr = ByteString

-- | Low level 'Cash32' is the human-readable low-level encoding used by 'CashAddr'. It
-- need not encode a valid address but any binary data.
type Cash32 = ByteString

-- | Internal type for encoding Base32 data.
type Word5 = Word8

-- | Symbols for encoding 'Cash32' data in human-readable strings.
charset :: [Char]
charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

-- | Get the 32-bit number associated with this 'Cash32' character.
base32char :: Char -> Maybe Word8
base32char = fmap fromIntegral . (`elemIndex` charset)

-- | High-Level: Decode 'CashAddr' string if it is valid for the
-- provided 'Network'. Prefix may be omitted from the string.
cashAddrDecode :: Network -> CashAddr -> Maybe (CashVersion, ByteString)
cashAddrDecode net ca' = do
    epfx <- getCashAddrPrefix net
    guard (B.length ca <= 90)
    guard (C.map toUpper ca' == ca' || ca == ca')
    let (cpfx', cdat) = C.breakEnd (== ':') ca
        cpfx
            | B.null cpfx' = epfx
            | otherwise = B.init cpfx'
    (dpfx, bs) <- cash32decode (epfx <> ":" <> cdat)
    guard (not (B.null bs))
    guard (dpfx == epfx)
    let len = decodeCashLength (B.head bs)
        ver = decodeCashVersion (B.head bs)
    guard (B.length (B.tail bs) == len)
    return (ver, B.tail bs)
  where
    ca = C.map toLower ca'

-- | High-Level: Encode 'CashAddr' string for the provided network and hash.
-- Fails if the 'CashVersion' or length of hash 'ByteString' is invalid.
cashAddrEncode :: Network -> CashVersion -> ByteString -> Maybe CashAddr
cashAddrEncode net cv bs = do
    pfx <- getCashAddrPrefix net
    ver <- encodeCashVersion cv
    len <- encodeCashLength (B.length bs)
    let vb = ver .|. len
        pl = vb `B.cons` bs
    return (cash32encode pfx pl)

-- | Low-Level: Decode 'Cash32' string. 'CashPrefix' must be part of the string.
-- No version or hash length validation is performed.
cash32decode :: Cash32 -> Maybe (CashPrefix, ByteString)
cash32decode bs' = do
    let bs = C.map toLower bs'
    guard (B.length bs' <= 90)
    guard (C.map toUpper bs' == bs' || bs == bs')
    let (pfx', dat) = C.breakEnd (== ':') bs
    pfx <-
        if B.null pfx' || pfx' == C.singleton ':'
            then Nothing
            else Just (B.init pfx')
    b32 <- B.pack <$> mapM base32char (C.unpack dat)
    let px = B.map (.&. 0x1f) pfx
        pd = px <> B.singleton 0 <> b32
        cs = cash32Polymod pd
        bb = B.take (B.length b32 - 8) b32
    guard (verifyCash32Polymod cs)
    let out = toBase256 bb
    return (pfx, out)

-- | Low-Level: Encode 'Cash32' string for 'CashPrefix' provided. Can encode
-- arbitrary data. No prefix or length validation is performed.
cash32encode :: CashPrefix -> ByteString -> Cash32
cash32encode pfx bs =
    let b32 = toBase32 bs
        px = B.map (.&. 0x1f) pfx
        pd = px <> B.singleton 0 <> b32 <> B.replicate 8 0
        cs = cash32Polymod pd
        c32 = B.map f (b32 <> cs)
        f = fromIntegral . ord . (charset !!) . fromIntegral
    in pfx <> ":" <> c32

-- | Convert base of 'ByteString' from eight bits per byte to five bits per
-- byte, adding padding as necessary.
toBase32 :: ByteString -> ByteString
toBase32 =
    B.pack .
    map fromIntegral . fst . convertBits True 8 5 . map fromIntegral . B.unpack

-- | Convert base of 'ByteString' from five to eight bits per byte. Ignore
-- padding to be symmetric with respect to 'toBase32' function.
toBase256 :: ByteString -> ByteString
toBase256 =
    B.pack .
    map fromIntegral . fst . convertBits False 5 8 . map fromIntegral . B.unpack

-- | Obtain 'CashVersion' from 'CashAddr' version byte.
decodeCashVersion :: Word8 -> Word8
decodeCashVersion ver = ver `shiftR` 3

-- | Encode 'CashVersion' from byte. Fail if version is larger than five bits,
-- since that is invalid.
encodeCashVersion :: Word8 -> Maybe Word8
encodeCashVersion ver = do
    guard (ver == ver .&. 0x1f)
    return (ver `shiftL` 3)

-- | Decode length of hash from 'CashAddr' version byte.
decodeCashLength :: Word8 -> Int
decodeCashLength w8 = lengths !! fromIntegral (w8 .&. 0x07)
  where
    lengths = [20, 24, 28, 32, 40, 48, 56, 64]

-- | Encode length of hash into a 'CashAddr' version byte.
encodeCashLength :: Int -> Maybe Word8
encodeCashLength len
    | len == 20 = Just 0
    | len == 24 = Just 1
    | len == 28 = Just 2
    | len == 32 = Just 3
    | len == 40 = Just 4
    | len == 48 = Just 5
    | len == 56 = Just 6
    | len == 64 = Just 7
    | otherwise = Nothing

-- | Calculate or validate checksum from base32 'ByteString' (excluding prefix).
cash32Polymod :: ByteString -> ByteString
cash32Polymod v =
    B.pack
        [fromIntegral (polymod `shiftR` (5 * (7 - i))) .&. 0x1f | i <- [0 .. 7]]
  where
    polymod = B.foldl' outer (1 :: Word64) v `xor` 1
    outer c d =
        let c0 = (fromIntegral (c `shiftR` 35) :: Word8)
            c' = ((c .&. 0x07ffffffff) `shiftL` 5) `xor` fromIntegral d
        in foldl' (inner c0) c' (zip [0 ..] generator)
    generator =
        [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]
    inner c0 c (b, g)
        | c0 `testBit` b = c `xor` g
        | otherwise = c

-- | Validate that polymod 'ByteString' (eight bytes) is equal to zero.
verifyCash32Polymod :: ByteString -> Bool
verifyCash32Polymod = (== B.replicate 8 0)
