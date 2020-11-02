# AES Key Extractor

This is a coursework implemented for the needs of the third year module "Applied-Security" in the University of Bristol. It demonstrates how a side-channel attack can be used to extract the key used by the mainstream AES algorithm when it is naively implemented. Lastly, some countermeasures are implemented so that such attacks are less effective. The main reference for this code is [1].

## Equipment

A Rasberry Pi board was used on which the implementation of AES was run. Secondly, an osciloscope which connects to the Rasberry Pi was used, so that traces of power usage of the Rasberry Pi can be extracted.

The code was developed in three main steps, in the following order:

### AES naive implementation:

First, AES was implemented by following its strict mathematical definition. No countermeasures for side-channel attacks are considered here.

### Attack:

Secondly, a side channel attack is implemented, demonstrating how the traces from the power usage of a processor that runs the AES implementation above, with a specific key can be used to extract that key.

### Countermeasures:

Some countermeasures in the AES implementation are incorporated so that the attack above is not effective.

## Bibliography:

[1] Stefan Mangard, Elisabeth Oswald, and Thomas Popp. 2007. Power Analysis Attacks: Revealing the Secrets of Smart Cards (Advances in Information Security). Springer-Verlag, Berlin, Heidelberg.
