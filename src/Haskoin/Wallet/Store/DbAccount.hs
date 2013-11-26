{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GADTs             #-}
{-# LANGUAGE TypeFamilies      #-}
module Haskoin.Wallet.Store.DbAccount 
( dbGetAcc
, cmdNewAcc
, cmdNewMS
, cmdAddKeys
, cmdAccInfo
, cmdListAcc
, cmdDumpKeys
, yamlAcc
, isMSAcc
) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Trans
import Control.Monad.Trans.Either

import Data.Time
import Data.Yaml
import Data.Maybe
import Data.List (nub)
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.Conduit as C

import Database.Persist
import Database.Persist.Sqlite
import Database.Persist.TH

import Haskoin.Wallet.Keys
import Haskoin.Wallet.Manager
import Haskoin.Wallet.TxBuilder
import Haskoin.Wallet.Store.Util
import Haskoin.Script
import Haskoin.Protocol
import Haskoin.Crypto
import Haskoin.Util

yamlAcc :: DbAccountGeneric b -> Value
yamlAcc acc = object $ concat
    [ [ "Name"       .= dbAccountName acc
      , "Tree"       .= dbAccountTree acc
      ]
    , datType, datWarn
    ]
    where msReq = fromJust $ dbAccountMsRequired acc
          msTot = fromJust $ dbAccountMsTotal acc
          ms    = unwords [show msReq,"of",show msTot]
          miss  = msTot - length (dbAccountMsKeys acc) - 1
          datType | isMSAcc acc = ["Type" .= unwords [ "Multisig", ms ]]
                  | otherwise   = ["Type" .= ("Regular" :: String)]
          datWarn | isMSAcc acc && miss > 0 =
                      [ (T.pack "Warning") .= 
                          unwords [show miss,"multisig keys missing"]
                      ]
                  | otherwise = []

isMSAcc :: DbAccountGeneric b -> Bool
isMSAcc acc = (isJust $ dbAccountMsRequired acc) && 
              (isJust $ dbAccountMsTotal acc) 

dbGetAcc :: ( PersistUnique m 
            , PersistMonadBackend m ~ b
            )
         => String 
         -> EitherT String m (Entity (DbAccountGeneric b))
dbGetAcc name = liftMaybe accErr =<< (getBy $ UniqueAccName name)
    where accErr = unwords ["dbGetAcc: Invalid account", name]

cmdNewAcc :: (PersistUnique m, PersistQuery m) 
         => String -> EitherT String m Value
cmdNewAcc name = do
    time <- liftIO getCurrentTime
    (Entity wk w) <- dbGetWallet "main"
    let keyM = loadMasterKey =<< (xPrvImport $ dbWalletMaster w)
    master <- liftMaybe keyErr keyM
    let deriv = fromIntegral $ dbWalletAccDerivation w + 1
        (k,i) = head $ accPubKeys master deriv
        acc   = DbAccount name 
                          (fromIntegral i) 
                          (concat ["m/",show i,"'/"])
                          (xPubExport $ runAccPubKey k)
                          (-1) (-1) 
                          Nothing Nothing [] time
    eAcc <- insert acc
    update wk [DbWalletAccDerivation =. fromIntegral i]
    return $ yamlAcc acc
    where keyErr = "dbNewAcc: Could not load master key"

cmdNewMS :: (PersistUnique m, PersistQuery m)
         => String -> Int -> Int -> [XPubKey]
         -> EitherT String m Value
cmdNewMS name m n mskeys = do
    time <- liftIO getCurrentTime
    let keys = nub mskeys
    unless (length keys < n) $ left 
        "dbNewMSAcc: Too many keys"
    unless (n <= 16 && n >= 1 && m <= n && m >= 1) $ left
        "dbNewMSAcc: Invalid multisig parameters"
    (Entity wk w) <- dbGetWallet "main"
    let keyM = loadMasterKey =<< (xPrvImport $ dbWalletMaster w)
    master <- liftMaybe keyErr keyM
    let deriv = fromIntegral $ dbWalletAccDerivation w + 1
        (k,i) = head $ accPubKeys master deriv
        acc   = DbAccount name 
                          (fromIntegral i) 
                          (concat ["m/",show i,"'/"])
                          (xPubExport $ runAccPubKey k)
                          (-1) (-1) 
                          (Just m) (Just n) 
                          (map xPubExport mskeys)
                          time
    eAcc <- insert acc
    update wk [DbWalletAccDerivation =. fromIntegral i]
    return $ yamlAcc acc
    where keyErr = "dbNewAcc: Could not load master key"

cmdAddKeys :: (PersistStore m, PersistUnique m, PersistQuery m)
           => AccountName -> [XPubKey] -> EitherT String m Value
cmdAddKeys name keys = do
    (Entity ai acc) <- dbGetAcc name
    unless (isMSAcc acc) $ left $ "cmdAddKeys: Not a multisig account"
    exists <- mapM (\x -> count [DbAccountKey ==. (xPubExport x)]) keys
    unless (sum exists == 0) $ left $
        "cmdAddKeys: Can not build a multisignature account with your own keys"
    prevKeys <- liftMaybe keyErr $ mapM xPubImport $ dbAccountMsKeys acc
    let newKeys = nub $ keys ++ prevKeys
        newAcc  = acc{ dbAccountMsKeys = map xPubExport newKeys }
    unless (length newKeys < (fromJust $ dbAccountMsTotal acc)) $ left $
        "cmdAddKeys: Too many keys"
    replace ai newAcc
    return $ yamlAcc newAcc
    where keyErr = "cmdAddKeys: Invalid keys found in account"

cmdAccInfo :: PersistUnique m => AccountName -> EitherT String m Value
cmdAccInfo name = yamlAcc . entityVal <$> dbGetAcc name

cmdListAcc :: PersistQuery m => EitherT String m Value
cmdListAcc = toJSON . (map (yamlAcc . entityVal)) <$> selectList [] []

cmdDumpKeys :: PersistUnique m => AccountName -> EitherT String m Value
cmdDumpKeys name = do
    (Entity _ w)   <- dbGetWallet "main"
    (Entity _ acc) <- dbGetAcc name
    let keyM = loadMasterKey =<< (xPrvImport $ dbWalletMaster w)
    master <- liftMaybe keyErr keyM
    prv <- liftMaybe prvErr $ 
        accPrvKey master (fromIntegral $ dbAccountDerivation acc)
    let prvKey = runAccPrvKey prv
        pubKey = deriveXPubKey prvKey
        ms | isMSAcc acc = ["MSKeys" .= (toJSON $ dbAccountMsKeys acc)]
           | otherwise   = []
    return $ object $
        [ "Account" .= yamlAcc acc
        , "PubKey"  .= xPubExport pubKey 
        , "PrvKey"  .= xPrvExport prvKey 
        ] ++ ms
    where keyErr = "cmdDumpKeys: Could not decode master key"
          prvErr = "cmdDumpKeys: Could not derive account private key"

