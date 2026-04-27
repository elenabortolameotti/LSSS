# LSSS

The idea of this library is to create a generalized shamir secret sharing scheme based on the following article: https://eprint.iacr.org/2025/277.pdf

We want to adapt the idea of the article to te special following case:

        (2,2)
         |
         /\
    (1,1)  (n,k)

Then, we want to adapt the scheme to a threshold signature scheme with also the verification of the consistency of the shares, using a schnorr-like signature.