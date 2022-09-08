{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Haskoin.Keys.Extended.Internal (
    Fingerprint (..),
    fingerprintToText,
    textToFingerprint,
) where

import Control.DeepSeq (NFData)
import Control.Monad ((>=>))
import Data.Bytes.Get (getWord32be, runGetS)
import Data.Bytes.Put (putWord32be, runPutS)
import Data.Bytes.Serial (Serial (..))
import Data.Either (fromRight)
import Data.Hashable (Hashable)
import Data.Maybe (fromMaybe)
import Data.String (IsString (..))
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Typeable (Typeable)
import Data.Word (Word32)
import GHC.Generics (Generic)
import Haskoin.Util (decodeHex, encodeHex)
import Text.Read (readEither, readPrec)


-- | Fingerprint of parent
newtype Fingerprint = Fingerprint {unFingerprint :: Word32}
    deriving (Eq, Ord, Hashable, Typeable, Generic, NFData)


fingerprintToText :: Fingerprint -> Text
fingerprintToText = encodeHex . runPutS . serialize


textToFingerprint :: Text -> Either String Fingerprint
textToFingerprint = maybe (Left "Fingerprint: invalid hex") Right . decodeHex >=> runGetS deserialize


instance Show Fingerprint where
    show = show . Text.unpack . encodeHex . runPutS . serialize


instance Read Fingerprint where
    readPrec =
        readPrec
            >>= maybe (fail "Fingerprint: invalid hex") pure . decodeHex
            >>= either (fail . ("Fingerprint: " <>)) pure . runGetS deserialize


instance IsString Fingerprint where
    fromString =
        fromRight decodeError
            . runGetS deserialize
            . fromMaybe hexError
            . decodeHex
            . Text.pack
        where
            decodeError = error "Fingerprint literal: Unable to decode"
            hexError = error "Fingerprint literal: Invalid hex"


instance Serial Fingerprint where
    serialize = putWord32be . unFingerprint
    deserialize = Fingerprint <$> getWord32be
