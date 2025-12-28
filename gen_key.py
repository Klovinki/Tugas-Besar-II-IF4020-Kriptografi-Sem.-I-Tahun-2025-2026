from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

priv = ec.generate_private_key(ec.SECP256R1())  # P-256
priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

with open("admin_private.pem", "wb") as f:
    f.write(priv_pem)

pub = priv.public_key()
pub_pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("admin_public.pem", "wb") as f:
    f.write(pub_pem)

print("Generated admin_private.pem and admin_public.pem")