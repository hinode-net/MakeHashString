-- | This is a wrapper library of Data.Digest.Pure.SHA.
-- This implementation is used in "String".
module Data.Digest.Pure.SHA.String (
	makeHashDigest,
	makeHmacHashDigest,
	makeHashString,
	makeHashStringBase64,
	makeHmacHashString,
	makeHmacHashStringBase64,
	showDigestBase64,

	makeSHA1HashString,
	makeSHA1HashStringBase64,
	makeHmacSHA1HashString,
	makeHmacSHA1HashStringBase64,
	makeSHA224HashString,
	makeSHA224HashStringBase64,
	makeHmacSHA224HashString,
	makeHmacSHA224HashStringBase64,
	makeSHA256HashString,
	makeSHA256HashStringBase64,
	makeHmacSHA256HashString,
	makeHmacSHA256HashStringBase64,
	makeSHA384HashString,
	makeSHA384HashStringBase64,
	makeHmacSHA384HashString,
	makeHmacSHA384HashStringBase64,
	makeSHA512HashString,
	makeSHA512HashStringBase64,
	makeHmacSHA512HashString,
	makeHmacSHA512HashStringBase64
) where

{-
sha256などでHashをStringとして生成するライブラリ
-}

import Prelude as P
-- for SHA256
import Data.Digest.Pure.SHA as S
-- for SHA256(ByteString)
import Data.ByteString.Lazy as B
import Data.ByteString.Internal as BI
-- for SHA256(String2Word82ByteString)
import Codec.Binary.UTF8.String as US
-- for SHA256(BASE64)
import Codec.Binary.Base64.String as B64S

-- | Make hash a Digest.
-- Digest型の状態で16進数のハッシュ生成
makeHashDigest
	:: (B.ByteString -> Digest)	-- ^ Data.Digest.Pure.SHA.sha1, sha224, sha256, sha384, or sha512
	-> String					-- ^ message
	-> Digest					-- ^ SHA-n MAC
makeHashDigest hf srcStr = hf $ toByteString srcStr

-- | Make HMAC hash a Digest.
-- hmacでDigest型の状態で16進数のハッシュ生成
makeHmacHashDigest
	:: (B.ByteString -> B.ByteString -> Digest)	-- ^ Data.Digest.Pure.SHA.hmacSha1, hmacSha224, hmacSha256, hmacSha384, or hmacSha512
	-> String								-- ^ secret key
	-> String								-- ^ message
	-> Digest								-- ^ SHA-n MAC
makeHmacHashDigest hf skey srcStr = hf (toByteString skey) $ toByteString srcStr

-- | Make hash string in hexadecimal number.
--ハッシュを生成する(16進数形式)
makeHashString
	:: (B.ByteString -> Digest)	-- ^ Data.Digest.Pure.SHA.Sha1, Sha224, Sha256, Sha384, or Sha512
	-> String					-- ^ message
	-> String					-- ^ SHA-n MAC
makeHashString hf srcStr = showDigest $ makeHashDigest hf srcStr

-- | Make hash string in BASE64.
-- ハッシュを生成する(BASE64形式)
makeHashStringBase64
	:: (B.ByteString -> Digest)	-- ^ Data.Digest.Pure.SHA.Sha1, Sha224, Sha256, Sha384, or Sha512
	-> String					-- ^ message
	-> String					-- ^ SHA-n MAC with BASE64
makeHashStringBase64 hf srcStr = showDigestBase64 $ makeHashDigest hf srcStr

-- | Make HMAC hash in hexadecimal number.
-- hmacでハッシュを生成する(16進数形式)
makeHmacHashString
	:: (B.ByteString -> B.ByteString -> Digest)	-- ^ Data.Digest.Pure.SHA.hmacSha1, hmacSha224, hmacSha256, hmacSha384, or hmacSha512
	-> String								-- ^ secret key
	-> String								-- ^ message
	-> String								-- ^ SHA-n MAC
makeHmacHashString hf skey srcStr = showDigest $ makeHmacHashDigest hf skey srcStr

-- | Make HMAC hash in BASE64.
-- hmacでハッシュを生成する(BASE64形式)
makeHmacHashStringBase64
	:: (B.ByteString -> B.ByteString -> Digest)	-- ^ Data.Digest.Pure.SHA.hmacSha1, hmacSha224, hmacSha256, hmacSha384, or hmacSha512
	-> String								-- ^ secret key
	-> String								-- ^ message
	-> String								-- ^ SHA-n MAC with BASE64
makeHmacHashStringBase64 hf skey srcStr = showDigestBase64 $ makeHmacHashDigest hf skey srcStr

{-
ラッパー関数群
-}

-- | Make hash string using SHA1 in BASE64.
-- SHA1でハッシュを生成する(BASE64形式)
makeSHA1HashStringBase64
	:: String		-- ^ message
	-> String		-- ^ SHA-n MAC with BASE64
makeSHA1HashStringBase64 srcStr = showDigestBase64 $ makeHashDigest sha1 srcStr

-- | Make hash string using SHA1 in hexadecimal number.
-- SHA1でハッシュを生成する(16進数形式)
makeSHA1HashString
	:: String		-- ^ message
	-> String		-- ^ SHA-n MAC
makeSHA1HashString srcStr = showDigest $ makeHashDigest sha1 srcStr

-- | Make HMAC hash using SHA1 in BASE64.
-- hmacSHA1でハッシュを生成する(BASE64形式)
makeHmacSHA1HashStringBase64
	:: String		-- ^ secret key
	-> String		-- ^ message
	-> String		-- ^ SHA-n MAC with BASE64
makeHmacSHA1HashStringBase64 skey srcStr = showDigestBase64 $ makeHmacHashDigest hmacSha1 skey srcStr

-- | Make HMAC hash using SHA1 in hexadecimal number.
-- hmacSHA1でハッシュを生成する(16進数形式)
makeHmacSHA1HashString
	:: String		-- ^ secret key
	-> String		-- ^ message
	-> String		-- ^ SHA-n MAC
makeHmacSHA1HashString skey srcStr = showDigest $ makeHmacHashDigest hmacSha1 skey srcStr


-- | Make hash string using SHA224 in BASE64.
-- SHA224でハッシュを生成する(BASE64形式)
makeSHA224HashStringBase64
	:: String		-- ^ message
	-> String		-- ^ SHA-n MAC with BASE64
makeSHA224HashStringBase64 srcStr = showDigestBase64 $ makeHashDigest sha224 srcStr

-- | Make hash string using SHA224 in hexadecimal number.
-- SHA224でハッシュを生成する(16進数形式)
makeSHA224HashString
	:: String		-- ^ message
	-> String		-- ^ SHA-n MAC
makeSHA224HashString srcStr = showDigest $ makeHashDigest sha224 srcStr

-- | Make HMAC hash using SHA224 in BASE64.
-- hmacSHA224でハッシュを生成する(BASE64形式)
makeHmacSHA224HashStringBase64
	:: String		-- ^ secret key
	-> String		-- ^ message
	-> String		-- ^ SHA-n MAC with BASE64
makeHmacSHA224HashStringBase64 skey srcStr = showDigestBase64 $ makeHmacHashDigest hmacSha224 skey srcStr

-- | Make HMAC hash using SHA224 in hexadecimal number.
-- hmacSHA224でハッシュを生成する(16進数形式)
makeHmacSHA224HashString
	:: String		-- ^ secret key
	-> String		-- ^ message
	-> String		-- ^ SHA-n MAC
makeHmacSHA224HashString skey srcStr = showDigest $ makeHmacHashDigest hmacSha224 skey srcStr


-- | Make hash string using SHA256 in BASE64.
-- SHA256でハッシュを生成する(BASE64形式)
makeSHA256HashStringBase64
	:: String		-- ^ message
	-> String		-- ^ SHA-n MAC with BASE64
makeSHA256HashStringBase64 srcStr = showDigestBase64 $ makeHashDigest sha256 srcStr

-- | Make hash string using SHA256 in hexadecimal number.
-- SHA256でハッシュを生成する(16進数形式)
makeSHA256HashString
	:: String		-- ^ message
	-> String		-- ^ SHA-n MAC
makeSHA256HashString srcStr = showDigest $ makeHashDigest sha256 srcStr

-- | Make HMAC hash using SHA256 in BASE64.
-- hmacSHA256でハッシュを生成する(BASE64形式)
makeHmacSHA256HashStringBase64
	:: String		-- ^ secret key
	-> String		-- ^ message
	-> String		-- ^ SHA-n MAC with BASE64
makeHmacSHA256HashStringBase64 skey srcStr = showDigestBase64 $ makeHmacHashDigest hmacSha256 skey srcStr

-- | Make HMAC hash using SHA256 in hexadecimal number.
-- hmacSHA256でハッシュを生成する(16進数形式)
makeHmacSHA256HashString
	:: String		-- ^ secret key
	-> String		-- ^ message
	-> String		-- ^ SHA-n MAC
makeHmacSHA256HashString skey srcStr = showDigest $ makeHmacHashDigest hmacSha256 skey srcStr


-- | Make hash string using SHA384 in BASE64.
-- SHA384でハッシュを生成する(BASE64形式)
makeSHA384HashStringBase64
	:: String		-- ^ message
	-> String		-- ^ SHA-n MAC with BASE64
makeSHA384HashStringBase64 srcStr = showDigestBase64 $ makeHashDigest sha384 srcStr

-- | Make hash string using SHA384 in hexadecimal number.
-- SHA384でハッシュを生成する(16進数形式)
makeSHA384HashString
	:: String		-- ^ message
	-> String		-- ^ SHA-n MAC
makeSHA384HashString srcStr = showDigest $ makeHashDigest sha384 srcStr

-- | Make HMAC hash using SHA384 in BASE64.
-- hmacSHA384でハッシュを生成する(BASE64形式)
makeHmacSHA384HashStringBase64
	:: String		-- ^ secret key
	-> String		-- ^ message
	-> String		-- ^ SHA-n MAC with BASE64
makeHmacSHA384HashStringBase64 skey srcStr = showDigestBase64 $ makeHmacHashDigest hmacSha384 skey srcStr

-- | Make HMAC hash using SHA384 in hexadecimal number.
-- hmacSHA384でハッシュを生成する(16進数形式)
makeHmacSHA384HashString
	:: String		-- ^ secret key
	-> String		-- ^ message
	-> String		-- ^ SHA-n MAC
makeHmacSHA384HashString skey srcStr = showDigest $ makeHmacHashDigest hmacSha384 skey srcStr


-- | Make hash string using SHA512 in BASE64.
-- SHA512でハッシュを生成する(BASE64形式)
makeSHA512HashStringBase64
	:: String		-- ^ message
	-> String		-- ^ SHA-n MAC with BASE64
makeSHA512HashStringBase64 srcStr = showDigestBase64 $ makeHashDigest sha512 srcStr

-- | Make hash string using SHA512 in hexadecimal number.
-- SHA512でハッシュを生成する(16進数形式)
makeSHA512HashString
	:: String		-- ^ message
	-> String		-- ^ SHA-n MAC
makeSHA512HashString srcStr = showDigest $ makeHashDigest sha512 srcStr

-- | Make HMAC hash using SHA512 in BASE64.
-- hmacSHA512でハッシュを生成する(BASE64形式)
makeHmacSHA512HashStringBase64
	:: String		-- ^ secret key
	-> String		-- ^ message
	-> String		-- ^ SHA-n MAC with BASE64
makeHmacSHA512HashStringBase64 skey srcStr = showDigestBase64 $ makeHmacHashDigest hmacSha512 skey srcStr

-- | Make HMAC hash using SHA512 in hexadecimal number.
-- hmacSHA512でハッシュを生成する(16進数形式)
makeHmacSHA512HashString
	:: String		-- ^ secret key
	-> String		-- ^ message
	-> String		-- ^ SHA-n MAC
makeHmacSHA512HashString skey srcStr = showDigest $ makeHmacHashDigest hmacSha512 skey srcStr



{-
	補助関数
-}

-- | Convert a digest to a string. The digest is rendered as fixed with BASE64.
-- DigestからBASE64形式のStringに変換する
showDigestBase64 :: Digest -> String
showDigestBase64 srcStr = B64S.encode $ P.map BI.w2c $ B.unpack $ bytestringDigest srcStr

-- | Convert a String to a Data.ByteString.Lazy.ByteString.
toByteString :: String -> B.ByteString
toByteString srcStr = B.pack $ US.encode srcStr
