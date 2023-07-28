from cardano.module import PaymentSigningKey,PaymentVerificationKey



payment_signing_key = PaymentSigningKey.generate()
payment_signing_key.save("payment.skey")

payment_verification_key = PaymentVerificationKey.from_signing_key(payment_signing_key)
payment_verification_key.save("payment_veryfication_key.vkey")