# Bintropy

Author : Kanimozhi Murugan

Bin entropy calculation using statistical test suite based on Discrete fourier transform of the sequence. The purpose is to detect the repetitive patterns that are near to each other in the sequence which would indicate a deviation from the assumption of randomness.

Malware detection by entropy - ascii entropy and binary entropy

Bin Entropy calculated based on 'Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications' published by National Institute of Standards and Technology, U.S Department of Commerce

Source : http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf

See "Using Entropy Analysis to Find Encrypted and Packed Malware" by Lyda Sparta and James Hamrock

----------
    FFT - scipy.fftpack
    pdfminer - PDF extraction tool
    Malware detection by entropy based on 'Using Entropy analysis to find encrypted and packed malware'
    published by IEEE Security and Privacy
    ascii_entropy - entropy calculation on ascii contents of the file range(0 - 8)

----------

- Python 2.7

----------
Modifications by Stephen Genusa 

- Removed Windows specific path for files (now defaults to same directory as .py program)
- Process the files in the directory one time and quit rather than an endless loop
- Added .lower() function on PDF filename check
- All files except PDF processed by bintropy() function
- Seeks 88 bytes into file before reading to skip an ASCII header on the files I was checking

----------

