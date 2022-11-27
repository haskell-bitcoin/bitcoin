{-# LANGUAGE OverloadedStrings #-}

-- |
-- Stability   : experimental
-- Portability : POSIX
--
-- ECDSA signatures using secp256k1 curve. Uses functions from upstream secp256k1
-- library.
module Bitcoin.Crypto.Signature (
    -- * Signatures
    putSig,
    getSig,
    signHash,
    verifyHashSig,
    isCanonicalHalfOrder,
    decodeStrictSig,
) where

import Bitcoin.Crypto.Hash
import Control.Monad (guard, unless, when)
import Crypto.Secp256k1
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Short (fromShort)
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Maybe (fromMaybe, isNothing)
import Data.Serialize (Serialize (..))
import Numeric (showHex)


-- | Sign a 256-bit hash using secp256k1 elliptic curve.
signHash :: SecKey -> Hash256 -> Maybe Signature
signHash k = ecdsaSign k . fromShort . getHash256


-- | Verify an ECDSA signature for a 256-bit hash.
verifyHashSig :: Hash256 -> Signature -> PubKeyXY -> Bool
verifyHashSig h s p = ecdsaVerify (fromShort $ getHash256 h) p norm
  where
    norm = fromMaybe s (normalizeSignature s)


-- | Deserialize an ECDSA signature as commonly encoded in Bitcoin.
getSig :: MonadGet m => m Signature
getSig = do
    l <-
        lookAhead $ do
            t <- getWord8
            -- 0x30 is DER sequence type
            unless (t == 0x30) $
                fail $
                    "Bad DER identifier byte 0x" ++ showHex t ". Expecting 0x30"
            l <- getWord8
            when (l == 0x00) $ fail "Indeterminate form unsupported"
            when (l >= 0x80) $ fail "Multi-octect length not supported"
            return $ fromIntegral l
    bs <- getByteString $ l + 2
    case decodeStrictSig bs of
        Just s -> return s
        Nothing -> fail "Invalid signature"


-- | Serialize an ECDSA signature for Bitcoin use.
putSig :: MonadPut m => Signature -> m ()
putSig s = putByteString $ exportSignatureDer s


-- | Is canonical half order.
isCanonicalHalfOrder :: Signature -> Bool
isCanonicalHalfOrder = isNothing . normalizeSignature


-- | Decode signature strictly.
decodeStrictSig :: ByteString -> Maybe Signature
decodeStrictSig bs = do
    g <- importSignatureDer bs
    -- <http://www.secg.org/sec1-v2.pdf Section 4.1.4>
    -- 4.1.4.1 (r and s can not be zero)
    let compact = exportSignatureCompact g
    let zero = BS.replicate 32 0
    guard $ BS.take 32 compact /= zero
    guard $ BS.take 32 (BS.drop 32 compact) /= zero
    guard $ isCanonicalHalfOrder g
    return g
