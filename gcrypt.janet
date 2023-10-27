
(ffi/context "/usr/lib/x86_64-linux-gnu/libgcrypt.so" :lazy true)

(ffi/defbind gcry-md-open :uint [h :ptr algo :int flags :uint])
(ffi/defbind gcry-md-setkey :uint [hd :ptr key :ptr keylen :size])
(ffi/defbind gcry-md-close :void [hd :ptr])
(ffi/defbind gcry-md-write :void [hd :ptr buffer :ptr length :size])
(ffi/defbind gcry-md-read :ptr [hd :ptr algo :int])
(ffi/defbind gcry-md-extract :uint [hd :ptr algo :int buffer :ptr length :size])

(ffi/defbind gcry-md-algo-name :string [algo :int])
(ffi/defbind gcry-md-map-name :int [name :string])
(ffi/defbind gcry-md-get-algo-dlen :int [algo :int])

(ffi/defbind gcry-md-hash-buffer :void
   [algo :int
    digest :ptr
    buffer :ptr
    length: :size])

(ffi/defbind gcry-kdf-derive :uint
   [passphrase :string
    passphraselen :size
    algo :int
    subalgo :int
    salt :string
    saltlen :size
    iterations :ulong
    keysize :size
    keybuffer :ptr])

(def pointer (ffi/struct :ptr))
(def hash-buffer (ffi/struct @[:uint8 64]))

(defn pbkdf2-sha512 [password salt iterations]
  (let [keylen 64
        keybuffer (buffer/new-filled keylen)
        result (gcry-kdf-derive password (length password) 34 10 salt (length salt) iterations keylen keybuffer)]
    (assert (zero? result))
    (string keybuffer)))

(defn hmac-sha512 [data secret]
  (let [ptr (ffi/write pointer [nil])
        result (gcry-md-open ptr 10 2)
        hd (get (ffi/read pointer ptr) 0)]
    (assert (zero? result))
    (def result (gcry-md-setkey hd secret (length secret)))
    (assert (zero? result))
    (gcry-md-write hd data (length data))
    (def md (string/from-bytes ;(get (ffi/read hash-buffer (gcry-md-read hd 0)) 0)))
    (gcry-md-close hd)
    md))
