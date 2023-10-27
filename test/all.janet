(use ../gcrypt)

(defn to-hex [msg]
  (string/join (seq [ch :in msg] (string/format "%02x" ch))))

(assert (= (to-hex (pbkdf2-sha512 "Mary had a little lamp" "salty" 1024))
		   "bd810fa504398e11fa7032ed98580eab5db9a19d1933d1e412f3bdb2c0887cac71c8f3d9466bb7c3eb53b7218be3346d5e6bf86c57be11ee2f1d655d4beed79f"))

(assert (= (to-hex (hmac-sha512 "Mary had a little lamp" "salty"))
		   "e42d80726e59b3b7470aabc5c2e6461075ef6a41be9eed41d04d2d87112e5f4a820fab1ee0e75299d94fcf11b47f0d3ea127d69104c336ce6a1692d3483d8828"))
