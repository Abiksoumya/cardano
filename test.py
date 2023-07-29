from cardano.module import PaymentSigningKey,PaymentVerificationKey,Network,Address



payment_signing_key = PaymentSigningKey.generate()
payment_signing_key.save("payment.skey")

payment_verification_key = PaymentVerificationKey.from_signing_key(payment_signing_key)
payment_verification_key.save("payment_veryfication_key.vkey")




network = Network.TESTNET
address = Address(payment_part=payment_verification_key.hash(), network=network)
print("the address id",address)
