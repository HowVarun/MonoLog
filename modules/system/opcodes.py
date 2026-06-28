class Opcodes:
    # =========================================================================
    # ROUTING CONTROL (R) - Managing the physical connection
    # =========================================================================
    PING      = b"R1000"  # "Are you still there?" (Sent with 8 random bytes)
    PONG      = b"R1001"  # "Yes, I am here." (Returns the 8 random bytes)
    ACQ_OK    = b"R2000"  # "I successfully acquired and saved your last data chunk."
    ACQ_FAIL  = b"R2001"  # "I failed to acquire the chunk (network glitch, disk error)."

    # =========================================================================
    # IDENTITY & AUTH (I) - The Pairing & Zero-Trust Handshakes
    # =========================================================================
    DSA_HASH  = b"I1000"  # "Here is the HASH of my public key."
    HASH_ERR  = b"I1001"  # "Your hash format is invalid or corrupted."
    
    DSA_PUB   = b"I2000"  # "Here is my full ML-DSA Public Key."
    PUB_ERR   = b"I2001"  # "Your public key failed mathematical validation."
    
    DEVC_ID   = b"I3000"  # "Here is my Device Name and OS Type (JSON)."
    ID_ERR    = b"I3001"  # "I could not parse your Device ID JSON."
    
    AUTH_PASS = b"I4000"  # "My human typed the correct SAS PIN!"
    AUTH_FAIL = b"I4001"  # "My human typed the wrong SAS PIN. Aborting."


    TRUST_QRY = b"I5000"  # "Am I still in your Trusted Devices database?"
    TRUST_YES = b"I5001"  # "Yes, I recognize you. We can sync."
    TRUST_NO  = b"I5002"  # "No you are new or deleted device."
    
    DEVC_RM   = b"I5003"  # I have deleted/not found you in my trusted devices. Remove me.
    TRUST_RM  = b"I5004"  # I have successfully deleted your connection as per reqest
    TRUST_NF  = b"I5005"  # I don't have you in my trusted devices


    # =========================================================================
    # VAULT & SYNC OPERATIONS (V) - Moving the actual data
    # =========================================================================
    SYNC_REQ  = b"V1000"  # "Do you have any pending vault updates for me?"
    SYNC_NUL  = b"V1001"  # "No, my queue is empty. You are up to date."
    SYNC_ERR  = b"V1002"  # "Sync failed to start (e.g., my DB is locked/busy)."
    
    VAULT_FULL= b"V2000"  # "Incoming: The entire Vault file."
    VFUL_ERR  = b"V2001"  # "I failed to process the Full Vault (e.g., corrupted file)."
    
    VAULT_META= b"V3000"  # "Incoming: A Metadata-only Vault Delta (Rename, Delete, Defrag)."
    VMETA_ERR = b"V3001"  # "I failed to apply the metadata update."

    VAULT_DATA= b"V4000"  # "Incoming: A File Data update (JSON + stream of bytes attached)."
    VDATA_ERR = b"V4001"  # "I failed to apply the data update (e.g., disk full, hash mismatch)."

    # =========================================================================
    # NUCLEAR OPERATIONS (N) - Highly destructive/sensitive commands
    # =========================================================================
    NUKE_REPL = b"N1000"  # "Force-delete your vault and replace it with mine."
    NUKE_ERR  = b"N1001"  # "Nuclear replace denied (e.g., human refused password prompt)."
    
    DEK_CHNG  = b"N2000"  # "We are rotating the master Data Encryption Key."
    DEK_ERR   = b"N2001"  # "Key rotation failed. Reverting to old key."

    # =========================================================================
    # TEARDOWN (X) - Hanging up the phone
    # =========================================================================
    BYE_GRACE = b"X0000"  # "We are finished. Disconnecting safely."
    BYE_FORCE = b"X1000"  # "Critical security/trust failure. Cutting the cord immediately."

    # =========================================================================
    # GRANULAR ERROR CODES (E) - System-level crashes
    # =========================================================================
    ERR_MATH  = b"E1000"  # Cryptography failed (signature mismatch, KEM failure).
    ERR_PARSE = b"E2000"  # Structural error (JSON decode or struct unpack failed).
    ERR_ENV   = b"E3000"  # OS-level error (Out of RAM, Disk Full, Permission Denied).
    ERR_NET   = b"E4000"  # Socket dropped mid-stream or timed out.
    ERR_FATAL = b"E9999"  # Generic / Unhandled Python exception.