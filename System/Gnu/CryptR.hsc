{-# LANGUAGE ForeignFunctionInterface, EmptyDataDecls #-}
-- | This package wraps @glibc@'s @crypt_r@ function in a thread-safe manner.
--
-- @
-- $ ghci -XOverloadedStrings
-- GHCi, version 6.12.3: http://www.haskell.org/ghc/  :? for help
-- Loading package ghc-prim ... linking ... done.
-- Loading package integer-gmp ... linking ... done.
-- Loading package base ... linking ... done.
-- Loading package ffi-1.0 ... linking ... done.
-- Prelude> :m + System.Gnu.CryptR Data.ByteString.Char8
-- Prelude System.Gnu.CryptR Data.ByteString.Char8> 'cryptR' \"password\" \"l3\"
-- Loading package bytestring-0.9.1.7 ... linking ... done.
-- Loading package nano-cryptr-0.1 ... linking ... done.
-- \"l3vmImyenGFYg\"
-- Prelude System.Gnu.CryptR Data.ByteString.Char8> 'cryptR' \"password1\" \"l3vmImyenGFYg\"
-- \"l3vmImyenGFYg\"
-- Prelude System.Gnu.CryptR Data.ByteString.Char8> x <- 'newCryptData'
-- Prelude System.Gnu.CryptR Data.ByteString.Char8> 'cryptRIO' x  \"password1\" \"l3vmImyenGFYg\"
-- \"l3vmImyenGFYg\"
-- Prelude System.Gnu.CryptR Data.ByteString.Char8> 'cryptRIO' x \"xpassword\" \"l3vmImyenGFYg\"
-- \"l3odRN01x86RU\"
-- Prelude System.Gnu.CryptR Data.ByteString.Char8> 'cryptRIO' x \"password\" \"l3vmImyenGFYg\"
-- \"l3vmImyenGFYg\"
-- Prelude System.Gnu.CryptR Data.ByteString.Char8> 'cryptRIO' x \"password\" \"$1$grufal$\"
-- \"$1$grufal$KyfLpXJJ32ZZw9EqqMSav1\"
-- Prelude System.Gnu.CryptR Data.ByteString.Char8> 'cryptRIO' x \"password1\" \"$1$grufal$\"
-- \"$1$grufal$xi8N0nP2Fl22TxyW68uvV.\"
-- Prelude System.Gnu.CryptR Data.ByteString.Char8> 'cryptRIO' x \"password1\" \"$1$grufal$KyfLpXJJ32ZZw9EqqMSav1\"
-- \"$1$grufal$xi8N0nP2Fl22TxyW68uvV.\"
-- Prelude System.Gnu.CryptR Data.ByteString.Char8> 'cryptRIO' x \"password\" \"$1$grufal$KyfLpXJJ32ZZw9EqqMSav1\"
-- \"$1$grufal$KyfLpXJJ32ZZw9EqqMSav1\"
-- @
module System.Gnu.CryptR
       ( CryptData
       , newCryptData
       , cryptRIO
       , cryptR
       ) where

import Control.Concurrent.MVar

import qualified Data.ByteString as B

import Foreign
import Foreign.C.String
import Foreign.C.Types
import Foreign.Marshal.Alloc

#include <crypt.h>

-- An empty data type to represent the c struct crypt_data
data CDOpaque

-- name the foreign call
foreign import ccall safe "crypt_r"
    crypt_r :: CString-> CString -> Ptr CDOpaque -> IO CString


-- | 'CryptData' is an opaque wrapper around the state used by
-- @crypt_r@.
newtype CryptData = CD (MVar (ForeignPtr CDOpaque))
instance Show CryptData where show _ = "<CryptData>"


-- | Create a new 'CryptData' value.  It uses 'ForeignPtr' to free the
-- underlying data structure properly when it is garbage collected.
newCryptData :: IO CryptData
newCryptData = do
    ptr <- mallocBytes #{size struct crypt_data}
    #{poke struct crypt_data, initialized} ptr (0 :: CInt)
    fptr <- newForeignPtr finalizerFree ptr
    mvar <- newMVar fptr
    return $ CD mvar


-- | This is a thread-safe interface to the functionality provided by
-- @glibc@'s @crypt_r@.  It protects against concurrent use of the
-- same 'CryptData' value internally.  This means that it's
-- potentially a performance bottleneck, and you may wish to use
-- multiple 'CryptData' values if high concurrency is necessary.
--
-- This interface avoids initializing a new 'CryptData' for each call,
-- as is done by the 'cryptR' call
cryptRIO :: CryptData -- ^ the 'CryptData' to use as scratch space
         -> B.ByteString -- ^ the @key@ value as described by @crypt_r@
         -> B.ByteString -- ^ the @salt@ value as described by @crypt_r@
         -> IO B.ByteString -- ^ the result of the call to @crypt_r@
cryptRIO (CD mvar) key salt = withMVar mvar (`withForeignPtr` crypt key salt)


-- | This is a pure, thread-safe interface to the functionality
-- provided by @glibc@'s @crypt_r@.  It uses @crypt_r@ internally,
-- allocating a single-use buffer for each call.  Because the buffer
-- is decently large and needs to be initialized for each call, this
-- function has significantly more overhead on multiple calls than
-- using 'newCryptData' followed by multiple uses of 'cryptRIO'.  This
-- is provided as a convenience function when the overhead is not as
-- important as the simplicity of this interface.
cryptR :: B.ByteString -- ^ the @key@ value as described in @crypt_r@
       -> B.ByteString -- ^ the @salt@ value as described in @crypt_r@
       -> B.ByteString -- ^ the result of the call to @crypt_r@
cryptR key salt = unsafePerformIO $ do
    allocaBytes #{size struct crypt_data} $ \ptr -> do
        #{poke struct crypt_data, initialized} ptr (0 :: CInt)
        crypt key salt ptr


-- Common implementation guts
crypt :: B.ByteString -> B.ByteString -> Ptr CDOpaque -> IO B.ByteString
crypt key salt ptr = do
    B.useAsCString key $ \k -> B.useAsCString salt $ \s -> do
        crypted <- crypt_r k s ptr
        B.packCString crypted
