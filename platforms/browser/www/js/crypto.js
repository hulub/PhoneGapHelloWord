"use strict";

var Curve = sjcl.ecc.curves['k256']; // secp256k1

/**
 * @constructor
 * @param {sjcl.ecc.point}
 *            commitment_point The commitment of the proof.
 * @param {sjcl.bn}
 *            challenge_bn The challenge of the proof.
 * @param {sjcl.bn}
 *            response_bn The response of the proof.
 */
var DiscreteLogarithmProof = function DiscreteLogarithmProof(commitment_point, challenge_bn, response_bn) {
  this.commitment_point = commitment_point;
  this.challenge_bn = challenge_bn;
  this.response_bn = response_bn;
};
DiscreteLogarithmProof.prototype = {
  /**
   * @param {sjcl.ecc.point}
   *            generator The generator of the public key (point).
   * @param {sjcl.ecc.point}
   *            public_key The public key (point) against which the proof is
   *            verified.
   * @return {boolean} Validation
   */
  verify: function verify(generator, public_key) {
    if (!this.verifyWithoutChallenge(generator, public_key)) return false;

    var hash_bits = sjcl.bitArray.concat(sjcl.bitArray.concat(pointToBits(generator, true), pointToBits(this.commitment_point, true)), pointToBits(public_key, true));
    var calculated_challenge_bn = hashToBn(hash_bits).mod(Curve.r);

    return this.challenge_bn.equals(calculated_challenge_bn);
  },

  /**
   * @param {sjcl.ecc.point}
   *            generator The generator of the public key (point).
   * @param {sjcl.ecc.point}
   *            public_key The public key (point) against which the proof is
   *            verified.
   * @return {boolean} Validation
   */
  verifyWithoutChallenge: function verifyWithoutChallenge(generator, public_key) {
    var left_hand_side_point = generator.mult(this.response_bn);
    var right_hand_side_point = addPoints(this.commitment_point, public_key.mult(this.challenge_bn));

    return pointEquals(left_hand_side_point, right_hand_side_point);
  },

  /**
   * @return {String} Proof encoded as a string including all values in hex format
   */
  toString: function toString() {
    var commitment_hex = sjcl.codec.hex.fromBits(pointToBits(this.commitment_point, true));
    var challenge_hex = sjcl.codec.hex.fromBits(this.challenge_bn.toBits());
    var response_hex = sjcl.codec.hex.fromBits(this.response_bn.toBits());

    return commitment_hex + "," + challenge_hex + "," + response_hex;
  }
};

DiscreteLogarithmProof.fromString = function (string) {
  var strings = string.split(",");

  switch (strings.length) {
    case 3:
      var commitment_point = pointFromBits(sjcl.codec.hex.toBits(strings[0]));
      var challenge_bn = sjcl.bn.fromBits(sjcl.codec.hex.toBits(strings[1]));
      var response_bn = sjcl.bn.fromBits(sjcl.codec.hex.toBits(strings[2]));

      if (!challenge_bn.equals(challenge_bn.mod(Curve.r))) throw new sjcl.exception.corrupt("invalid value for challenge");
      if (!response_bn.equals(response_bn.mod(Curve.r))) throw new sjcl.exception.corrupt("invalid value for response");

      return new DiscreteLogarithmProof(commitment_point, challenge_bn, response_bn);
      break;
    default:
      throw new sjcl.exception.corrupt("invalid number of arguments in encoding");
      break;
  }
};

/**
 * @param {sjcl.ecc.point}
 *            generator The generator of the public key (point).
 * @param {sjcl.bn}
 *            private_key The private key of the proof (the knowledge).
 * @return {DiscreteLogarithmProof} A discrete logarithm zk proof of the knowledge.
 */
DiscreteLogarithmProof.generate = function (generator, private_key) {
  var commitment_bn = sjcl.bn.random(Curve.r);
  var commitment_point = generator.mult(commitment_bn);
  var public_key = generator.mult(private_key);

  var hash_bits = sjcl.bitArray.concat(sjcl.bitArray.concat(pointToBits(generator, true), pointToBits(commitment_point, true)), pointToBits(public_key, true));
  var challenge_bn = hashToBn(hash_bits).mod(Curve.r);

  var response_bn = commitment_bn.add(private_key.mul(challenge_bn)).mod(Curve.r);

  return new DiscreteLogarithmProof(commitment_point, challenge_bn, response_bn);
};

/**
 * @constructor
 * @param {sjcl.ecc.point}
 *            commitment_point_1 The first commitment of the proof.
 * @param {sjcl.ecc.point}
 *            commitment_point_2 The second commitment of the proof.
 * @param {sjcl.bn}
 *            challenge_bn The challenge of the proof.
 * @param {sjcl.bn}
 *            response_bn The response of the proof.
 */
var DiscreteLogarithmEqualityProof = function DiscreteLogarithmEqualityProof(commitment_point_1, commitment_point_2, challenge_bn, response_bn) {
  this.commitment_point_1 = commitment_point_1;
  this.commitment_point_2 = commitment_point_2;
  this.challenge_bn = challenge_bn;
  this.response_bn = response_bn;
};
DiscreteLogarithmEqualityProof.prototype = {
  /**
   * @param {sjcl.ecc.point}
   *            generator_1 The generator of the first public key (point).
   * @param {sjcl.ecc.point}
   *            generator_2 The generator of the second public key (point).
   * @param {sjcl.ecc.point}
   *            public_key_1 The first public key (point) against which the proof
   *            is verified.
   * @param {sjcl.ecc.point}
   *            public_key_2 The second public key (point) against which the proof
   *            is verified.
   * @return {boolean} Validation
   */
  verify: function verify(generator_1, generator_2, public_key_1, public_key_2) {
    if (!this.verifyWithoutChallenge(generator_1, generator_2, public_key_1, public_key_2)) return false;

    var hash_bits = sjcl.bitArray.concat(sjcl.bitArray.concat(sjcl.bitArray.concat(sjcl.bitArray.concat(sjcl.bitArray.concat(pointToBits(generator_1, true), pointToBits(generator_2, true)), pointToBits(this.commitment_point_1, true)), pointToBits(this.commitment_point_2, true)), pointToBits(public_key_1, true)), pointToBits(public_key_2, true));
    var calculated_challenge_bn = hashToBn(hash_bits).mod(Curve.r);

    return this.challenge_bn.equals(calculated_challenge_bn);
  },

  /**
   * @param {sjcl.ecc.point}
   *            generator_1 The generator of the first public key (point).
   * @param {sjcl.ecc.point}
   *            generator_2 The generator of the second public key (point).
   * @param {sjcl.ecc.point}
   *            public_key_1 The first public key (point) against which the proof
   *            is verified.
   * @param {sjcl.ecc.point}
   *            public_key_2 The second public key (point) against which the proof
   *            is verified.
   * @return {boolean} Validation
   */
  verifyWithoutChallenge: function verifyWithoutChallenge(generator_1, generator_2, public_key_1, public_key_2) {
    var left_hand_side_point_1 = generator_1.mult(this.response_bn);
    var right_hand_side_point_1 = addPoints(this.commitment_point_1, public_key_1.mult(this.challenge_bn));

    var left_hand_side_point_2 = generator_2.mult(this.response_bn);
    var right_hand_side_point_2 = addPoints(this.commitment_point_2, public_key_2.mult(this.challenge_bn));

    return pointEquals(left_hand_side_point_1, right_hand_side_point_1) && pointEquals(left_hand_side_point_2, right_hand_side_point_2);
  },

  /**
   * @return {String} Proof encoded as a string including all values in hex format
   */
  toString: function toString() {
    var commitment_1_hex = sjcl.codec.hex.fromBits(pointToBits(this.commitment_point_1, true));
    var commitment_2_hex = sjcl.codec.hex.fromBits(pointToBits(this.commitment_point_2, true));
    var challenge_hex = sjcl.codec.hex.fromBits(this.challenge_bn.toBits());
    var response_hex = sjcl.codec.hex.fromBits(this.response_bn.toBits());

    return commitment_1_hex + "," + commitment_2_hex + "," + challenge_hex + "," + response_hex;
  }
};

DiscreteLogarithmEqualityProof.fromString = function (string) {
  var strings = string.split(",");

  switch (strings.length) {
    case 4:
      var commitment_point_1 = pointFromBits(sjcl.codec.hex.toBits(strings[0]));
      var commitment_point_2 = pointFromBits(sjcl.codec.hex.toBits(strings[1]));
      var challenge_bn = sjcl.bn.fromBits(sjcl.codec.hex.toBits(strings[2]));
      var response_bn = sjcl.bn.fromBits(sjcl.codec.hex.toBits(strings[3]));

      if (!challenge_bn.equals(challenge_bn.mod(Curve.r))) throw new sjcl.exception.corrupt("invalid value for challenge");
      if (!response_bn.equals(response_bn.mod(Curve.r))) throw new sjcl.exception.corrupt("invalid value for response");

      return new DiscreteLogarithmEqualityProof(commitment_point_1, commitment_point_2, challenge_bn, response_bn);
      break;
    default:
      throw new sjcl.exception.corrupt("invalid number of arguments in encoding");
      break;
  }
};

/**
 * @param {sjcl.ecc.point}
 *            generator_1 The generator of the first public key (point).
 * @param {sjcl.ecc.point}
 *            generator_2 The generator of the second public key (point).
 * @param {sjcl.bn}
 *            private_key The private key of the proof (the knowledge).
 * @return {DiscreteLogarithmEqualityProof} A discrete logarithm equality zk proof for this
 *         private key
 */
DiscreteLogarithmEqualityProof.generate = function (generator_1, generator_2, private_key) {
  var commitment_bn = sjcl.bn.random(Curve.r);
  var commitment_point_1 = generator_1.mult(commitment_bn);
  var commitment_point_2 = generator_2.mult(commitment_bn);

  var hash_bits = sjcl.bitArray.concat(sjcl.bitArray.concat(sjcl.bitArray.concat(sjcl.bitArray.concat(sjcl.bitArray.concat(pointToBits(generator_1, true), pointToBits(generator_2, true)), pointToBits(commitment_point_1, true)), pointToBits(commitment_point_2, true)), pointToBits(generator_1.mult(private_key), true)), pointToBits(generator_2.mult(private_key), true));
  var challenge_bn = hashToBn(hash_bits).mod(Curve.r);

  var response_bn = commitment_bn.add(private_key.mul(challenge_bn)).mod(Curve.r);

  return new DiscreteLogarithmEqualityProof(commitment_point_1, commitment_point_2, challenge_bn, response_bn);
};

/**
 * @constructor
 * @param {sjcl.ecc.point}
 *            commitment_point The commitment of the proof.
 * @param {sjcl.bn}
 *            challenge_bn The challenge of the proof.
 * @param {sjcl.bn}
 *            response_bn The response of the proof.
 */
var DiscreteLogarithmMultipleProof = function DiscreteLogarithmMultipleProof(commitment_point, challenge_bn, response_bn) {
  this.commitment_point = commitment_point;
  this.challenge_bn = challenge_bn;
  this.response_bn = response_bn;
};
DiscreteLogarithmMultipleProof.prototype = {
  /**
   * @param {array of sjcl.ecc.point}
   *            generators The array of generators of the public keys (points).
   * @param {array of sjcl.ecc.point}
   *            public_keys The array of public keys (points) against which the proof is
   *            verified.
   * @return {boolean} Validation
   */
  verify: function verify(generators, public_keys) {
    if (!this.verifyWithoutChallenge(generators, public_keys)) return false;

    var hash_bits = [];
    generators.forEach(function (generator) {
      hash_bits = sjcl.bitArray.concat(hash_bits, pointToBits(generator, true));
    });
    hash_bits = sjcl.bitArray.concat(hash_bits, pointToBits(this.commitment_point, true));
    public_keys.forEach(function (public_key) {
      hash_bits = sjcl.bitArray.concat(hash_bits, pointToBits(public_key, true));
    });
    var calculated_challenge_bn = hashToBn(hash_bits).mod(Curve.r);

    return this.challenge_bn.equals(calculated_challenge_bn);
  },

  /**
   * @param {array of sjcl.ecc.point}
   *            generators The array of generators of the public keys (points).
   * @param {array of sjcl.ecc.point}
   *            public_keys The array of public keys (points) against which the proof is
   *            verified.
   * @return {boolean} Validation
   */
  verifyWithoutChallenge: function verifyWithoutChallenge(generators, public_keys) {
    if (generators.length != public_keys.length) return false;
    var n = generators.length - 1;

    var hash_bits = [];
    public_keys.forEach(function (public_key) {
      hash_bits = sjcl.bitArray.concat(hash_bits, pointToBits(public_key, true));
    });
    var hash = sjcl.hash.sha256.hash(hash_bits);

    var z = [];
    for (var i = 1; i <= n; i++) {
      hash_bits = sjcl.bitArray.concat(sjcl.codec.utf8String.toBits(i.toString()), hash);
      z[i - 1] = hashToBn(hash_bits).mod(Curve.r);
    }

    var left_hand_side_point = generators[0];
    for (var i = 0; i < n; i++) {
      left_hand_side_point = addPoints(left_hand_side_point, generators[i + 1].mult(z[i]));
    }
    left_hand_side_point = left_hand_side_point.mult(this.response_bn);

    var right_hand_side_point = public_keys[0];
    for (var i = 0; i < n; i++) {
      right_hand_side_point = addPoints(right_hand_side_point, public_keys[i + 1].mult(z[i]));
    }
    right_hand_side_point = addPoints(this.commitment_point, right_hand_side_point.mult(this.challenge_bn));

    return pointEquals(left_hand_side_point, right_hand_side_point);
  },

  /**
   * @return {String} Proof encoded as a string including all values in hex format
   */
  toString: function toString() {
    var commitment_hex = sjcl.codec.hex.fromBits(pointToBits(this.commitment_point, true));
    var challenge_hex = sjcl.codec.hex.fromBits(this.challenge_bn.toBits());
    var response_hex = sjcl.codec.hex.fromBits(this.response_bn.toBits());

    return commitment_hex + "," + challenge_hex + "," + response_hex;
  }
};

DiscreteLogarithmMultipleProof.fromString = function (string) {
  var strings = string.split(",");

  switch (strings.length) {
    case 3:
      var commitment_point = pointFromBits(sjcl.codec.hex.toBits(strings[0]));
      var challenge_bn = sjcl.bn.fromBits(sjcl.codec.hex.toBits(strings[1]));
      var response_bn = sjcl.bn.fromBits(sjcl.codec.hex.toBits(strings[2]));

      if (!challenge_bn.equals(challenge_bn.mod(Curve.r))) throw new sjcl.exception.corrupt("invalid value for challenge");
      if (!response_bn.equals(response_bn.mod(Curve.r))) throw new sjcl.exception.corrupt("invalid value for response");

      return new DiscreteLogarithmMultipleProof(commitment_point, challenge_bn, response_bn);
      break;
    default:
      throw new sjcl.exception.corrupt("invalid number of arguments in encoding");
      break;
  }
};

/**
 * @param {array of sjcl.ecc.point}
 *            generators The array of generators of the public keys (points).
 * @param {sjcl.bn}
 *            private_key The private key of the proof (the knowledge).
 * @return {DiscreteLogarithmMultipleProof} A discrete logarithm multiple zk proof of the knowledge.
 */
DiscreteLogarithmMultipleProof.generate = function (generators, private_key) {
  var n = generators.length - 1;
  var public_keys = generators.map(function (generator) {
    return generator.mult(private_key);
  });
  var commitment_bn = sjcl.bn.random(Curve.r);

  var hash_bits = [];
  public_keys.forEach(function (public_key) {
    hash_bits = sjcl.bitArray.concat(hash_bits, pointToBits(public_key, true));
  });
  var hash = sjcl.hash.sha256.hash(hash_bits);

  var z = [];
  for (var i = 1; i <= n; i++) {
    hash_bits = sjcl.bitArray.concat(sjcl.codec.utf8String.toBits(i.toString()), hash);
    z[i - 1] = hashToBn(hash_bits).mod(Curve.r);
  }

  var commitment_point = generators[0];
  for (var i = 0; i < n; i++) {
    commitment_point = addPoints(commitment_point, generators[i + 1].mult(z[i]));
  }
  commitment_point = commitment_point.mult(commitment_bn);

  hash_bits = [];
  generators.forEach(function (generator) {
    hash_bits = sjcl.bitArray.concat(hash_bits, pointToBits(generator, true));
  });
  hash_bits = sjcl.bitArray.concat(hash_bits, pointToBits(commitment_point, true));
  public_keys.forEach(function (public_key) {
    hash_bits = sjcl.bitArray.concat(hash_bits, pointToBits(public_key, true));
  });
  var challenge_bn = hashToBn(hash_bits).mod(Curve.r);

  var response_bn = commitment_bn.add(private_key.mul(challenge_bn)).mod(Curve.r);

  return new DiscreteLogarithmMultipleProof(commitment_point, challenge_bn, response_bn);
};

/**
 * @constructor
 * @param {sjcl.ecc.point}
 *            randomness_point The point representing the randomness used in this
 *            cryptogram.
 * @param {sjcl.bn}
 *            ciphertext_bn The number (ciphertext) encoding the message.
 */
var ElGamalScalarCryptogram = function ElGamalScalarCryptogram(randomness_point, ciphertext_bn) {
  this.randomness_point = randomness_point;
  this.ciphertext_bn = ciphertext_bn;
};
ElGamalScalarCryptogram.prototype = {
  /**
   * @param {sjcl.bn}
   *            private_key The decryption key, in form of big integer.
   * @return {sjcl.bn} The decrypted message, in form of big integer (scalar).
   */
  decrypt: function decrypt(private_key) {
    var secret_point = this.randomness_point.mult(private_key);
    var secret_bn = hashToBn(pointToBits(secret_point, true)).mod(Curve.r);
    var secret_bn_inverse = secret_bn.inverseMod(Curve.r);

    return this.ciphertext_bn.mul(secret_bn_inverse).mod(Curve.r);
  },

  /**
   * @return {String} Cryptogram encoded as a string including all values in hex format
   */
  toString: function toString() {
    var randomness_hex = sjcl.codec.hex.fromBits(pointToBits(this.randomness_point, true));
    var ciphertext_hex = sjcl.codec.hex.fromBits(this.ciphertext_bn.toBits());

    return randomness_hex + "," + ciphertext_hex;
  }
};

ElGamalScalarCryptogram.fromString = function (string) {
  var strings = string.split(",");

  switch (strings.length) {
    case 2:
      var randomness_point = pointFromBits(sjcl.codec.hex.toBits(strings[0]));
      var ciphertext_bn = sjcl.bn.fromBits(sjcl.codec.hex.toBits(strings[1]));

      if (!ciphertext_bn.equals(ciphertext_bn.mod(Curve.r))) throw new sjcl.exception.corrupt("invalid value for ciphertext");

      return new ElGamalScalarCryptogram(randomness_point, ciphertext_bn);
      break;
    default:
      throw new sjcl.exception.corrupt("invalid number of arguments in encoding");
      break;
  }
};

/**
 * @param {sjcl.bn}
 *            scalar The message (scalar) to be encrypted.
 * @param {sjcl.ecc.point}
 *            public_key The key to encrypt with.
 * @param {sjcl.bn}
 *            randomness_bn The random value (scalar) used in encryption.
 * @return {ElGamalScalarCryptogram} The cryptogram encoding the message
 */
ElGamalScalarCryptogram.encrypt = function (scalar, public_key, randomness_bn) {
  var randomness_point = Curve.G.mult(randomness_bn);
  var secret_point = public_key.mult(randomness_bn);

  var secret_bn = hashToBn(pointToBits(secret_point, true)).mod(Curve.r);

  var ciphertext_bn = scalar.mul(secret_bn).mod(Curve.r);

  return new ElGamalScalarCryptogram(randomness_point, ciphertext_bn);
};

/**
 * @constructor
 * @param {sjcl.ecc.point}
 *            randomness_point The point representing the randomness used in this
 *            cryptogram.
 * @param {sjcl.ecc.point}
 *            ciphertext_point The point (cyphertext) encoding the message.
 */
var ElGamalPointCryptogram = function ElGamalPointCryptogram(randomness_point, ciphertext_point) {
  this.randomness_point = randomness_point;
  this.ciphertext_point = ciphertext_point;
};

ElGamalPointCryptogram.prototype = {
  /**
   * @param {sjcl.bn}
   *            private_key The decryption key, in form of big integer.
   * @return {sjcl.ecc.point} The decrypted message, in form of point.
   */
  decrypt: function decrypt(private_key) {
    var secret_point = this.randomness_point.mult(private_key);

    return addPoints(this.ciphertext_point, secret_point.negate());
  },

  homomorphicallyAddCryptogram: function(other_cryptogram) {
    this.randomness_point = addPoints(this.randomness_point, other_cryptogram.randomness_point)
    this.ciphertext_point = addPoints(this.ciphertext_point, other_cryptogram.ciphertext_point)
  },

  /**
   * @return {String} Cryptogram encoded as a string including all values in hex format
   */
  toString: function toString() {
    var randomness_hex = sjcl.codec.hex.fromBits(pointToBits(this.randomness_point, true));
    var ciphertext_hex = sjcl.codec.hex.fromBits(pointToBits(this.ciphertext_point, true));

    return randomness_hex + "," + ciphertext_hex;
  }
};

ElGamalPointCryptogram.fromString = function (string) {
  var strings = string.split(",");

  switch (strings.length) {
    case 2:
      var randomness_point = pointFromBits(sjcl.codec.hex.toBits(strings[0]));
      var ciphertext_point = pointFromBits(sjcl.codec.hex.toBits(strings[1]));

      return new ElGamalPointCryptogram(randomness_point, ciphertext_point);
      break;
    default:
      throw new sjcl.exception.corrupt("invalid number of arguments in encoding");
      break;
  }
};

/**
 * @param {sjcl.ecc.point}
 *            point The message (point) to be encrypted.
 * @param {sjcl.ecc.point}
 *            public_key The key to encrypt with.
 * @param {sjcl.bn}
 *            randomness_bn The random value (scalar) used in encryption.
 * @return {ElGamalPointCryptogram} The cryptogram encoding the message
 */
ElGamalPointCryptogram.encrypt = function (point, public_key, randomness_bn) {
  var randomness_point = Curve.G.mult(randomness_bn);

  var secret_point = public_key.mult(randomness_bn);

  var ciphertext_point = secret_point;
  if (point) ciphertext_point = addPoints(ciphertext_point, point);

  return new ElGamalPointCryptogram(randomness_point, ciphertext_point);
};

/**
 * @constructor
 * @param {sjcl.bn} payload_bn The payload of the signature, representing the hash
 * of the commitment and the message as a big integer.
 * @param {sjcl.bn} signature_bn The signature as a big integer.
 */
var SchnorrSignature = function SchnorrSignature(payload_bn, signature_bn) {
  this.payload_bn = payload_bn;
  this.signature_bn = signature_bn;
};

SchnorrSignature.prototype = {
  /**
   * @param {sjcl.ecc.point} public_key The public key.
   * @param {String} message The signed message.
   * @return {boolean} Validation
   */
  verify: function verify(public_key, message) {
    var commitment_point = addPoints(Curve.G.mult(this.signature_bn), public_key.mult(this.payload_bn));

    var hash_bits = sjcl.bitArray.concat(pointToBits(commitment_point, true), sjcl.codec.utf8String.toBits(message));
    var payload_calculated_bn = hashToBn(hash_bits).mod(Curve.r);

    return payload_calculated_bn.equals(this.payload_bn);
  },

  /**
   * @return {String} Signature encoded as a string including all values in hex format
   */
  toString: function toString() {
    var payload_hex = sjcl.codec.hex.fromBits(this.payload_bn.toBits());
    var signature_hex = sjcl.codec.hex.fromBits(this.signature_bn.toBits());

    return payload_hex + "," + signature_hex;
  }
};

SchnorrSignature.fromString = function (string) {
  var strings = string.split(",");

  switch (strings.length) {
    case 2:
      var payload_bn = sjcl.bn.fromBits(sjcl.codec.hex.toBits(strings[0]));
      var signature_bn = sjcl.bn.fromBits(sjcl.codec.hex.toBits(strings[1]));

      if (!payload_bn.equals(payload_bn.mod(Curve.r))) throw new sjcl.exception.corrupt("invalid value for payload");
      if (!signature_bn.equals(signature_bn.mod(Curve.r))) throw new sjcl.exception.corrupt("invalid value for signature");

      return new SchnorrSignature(payload_bn, signature_bn);
      break;
    default:
      throw new sjcl.exception.corrupt("invalid number of arguments in encoding");
      break;
  }
};

/**
 * @param {String} message the message to be signed
 * @param {sjcl.bn} privatekey The private key of the signer.
 * @return {SchnorrSignature} A Schnorr signature tuple.
 */
SchnorrSignature.sign = function (message, private_key) {
  var commitment_bn = randomBN();
  var commitment_point = Curve.G.mult(commitment_bn);

  var hash_bits = sjcl.bitArray.concat(pointToBits(commitment_point, true), sjcl.codec.utf8String.toBits(message));
  var payload_bn = hashToBn(hash_bits).mod(Curve.r);

  var signature_bn = commitment_bn.sub(private_key.mul(payload_bn)).mod(Curve.r);

  return new SchnorrSignature(payload_bn, signature_bn);
};

// new methods for the sjcl library
function pointEquals(point_1, point_2) {
  if (point_1.isIdentity)
    return point_2.isIdentity

  if (point_2.isIdentity)
    return false

  return point_1.x.equals(point_2.x) && point_1.y.equals(point_2.y);
}

/**
 * @param {Point}
 *            point to be encoded as bits.
 * @param {boolean}
 *            compressed Compressed or uncompressed form (33 or 65 bytes).
 * @return {bitArray} The encoded data in form of bits.
 */
function pointToBits(point, compressed) {
  if (point.isIdentity) {
    var flag_bits = sjcl.codec.bytes.toBits([0x00]);
    return flag_bits;
  } else if (compressed) {
    var flag = 0x02 | point.y.limbs[0] & 0x01;
    var _flag_bits = sjcl.codec.bytes.toBits([flag == 2 ? 0x02 : 0x03]);
    var data_bits = point.x.toBits();
    return sjcl.bitArray.concat(_flag_bits, data_bits);
  } else {
    var _flag_bits2 = sjcl.codec.bytes.toBits([0x04]);
    var _data_bits = sjcl.bitArray.concat(point.x.toBits(), point.y.toBits());
    return sjcl.bitArray.concat(_flag_bits2, _data_bits);
  }
}

function addPoints(point_1, point_2) {
  return point_1.toJac().add(point_2).toAffine();
}

function pointFromBits(bits) {
  var type = sjcl.bitArray.extract(bits, 0, 8);
  var x = void 0,
      y = void 0,
      bn_bits = void 0;

  switch (type) {
    case 0:
      return new sjcl.ecc.point(Curve);
    case 2:
      bn_bits = sjcl.bitArray.bitSlice(bits, 8, 8 + 8 * 32);
      x = sjcl.bn.fromBits(bn_bits);
      y = recoverYfromX(x, 0);
      break;
    case 3:
      bn_bits = sjcl.bitArray.bitSlice(bits, 8, 8 + 8 * 32);
      x = sjcl.bn.fromBits(bn_bits);
      y = recoverYfromX(x, 1);
      break;
    case 4:
      bn_bits = sjcl.bitArray.bitSlice(bits, 8, 8 + 8 * 32);
      x = sjcl.bn.fromBits(bn_bits);
      bn_bits = sjcl.bitArray.bitSlice(bits, 8 + 8 * 32, 8 + 8 * 32 + 8 * 32);
      y = sjcl.bn.fromBits(bn_bits);
      break;
  }

  var p = new sjcl.ecc.point(Curve, new Curve.field(x), new Curve.field(y));

  if (!p.isValid()) {
    throw new sjcl.exception.corrupt("not on the curve!");
  }
  return p;
}

// helper methods

function randomBN() {
  return sjcl.bn.random(Curve.r);
}

function randomPoint() {
  while (true) {
    var flag_byte = Math.random() >= 0.5 ? 0x02 : 0x03;
    var flag_bits = sjcl.codec.bytes.toBits([flag_byte]);

    var x_bn = sjcl.bn.random(Curve.field.modulus);

    var point_bits = sjcl.bitArray.concat(flag_bits, x_bn.toBits());

    try {
      var point = pointFromBits(point_bits);
      return point;
    } catch (err) {}
  }
}

/**
 * @param {sjcl.bn}
 *            x The x coordonate as a bignum.
 * @param {bit}
 *            odd The public key (point) against which the proof is verified.
 * @return {sjcl.bn} The y coordinate, freshly calculated.
 */
function recoverYfromX(x, odd) {
  var prime = Curve.field.modulus;
  var y2 = Curve.b.add(x.mulmod(Curve.a.add(x.square().mod(prime)).mod(prime), prime)).mod(prime);

  var p = prime.add(1);
  p.halveM();
  p.halveM();

  var y = y2.powermod(p, prime);

  if ((y.limbs[0] & 1) != odd) {
    y = prime.sub(y).normalize();
  }

  return y;
};

function hashToBn(bits) {
  var bn_bits = sjcl.hash.sha256.hash(bits);
  return sjcl.bn.fromBits(bn_bits);
};




// encoding vote methods

var vote_encoding_types = Object.freeze({
  "BLANK" :0,
  "TEXT"  :1,
  "IDS"   :2
})

function voteToPoint(vote_encoding_type, vote) {
  // turn vote into bignum (used as x coordinate of the point) by:
  // [type bits] + [padding bits] + [vote bits] + [0x00 bits] (last byte is for
  // incrementing)
  // prepend the flag bits and try to decode point
  // if not on the curve, increment the x bignum and retry

  var vote_bits
  var padding_bytes_length

  switch (vote_encoding_type) {
    case vote_encoding_types.BLANK:
      return new sjcl.ecc.point(Curve)
      break;
    case vote_encoding_types.TEXT:
      // the vote is a text
      var text = vote
      vote_bits = sjcl.codec.utf8String.toBits(text)
      padding_bytes_length = 32 - 1 - 1 - sjcl.codec.bytes.fromBits(vote_bits).length
      break;
    case vote_encoding_types.IDS:
      // the vote is an array of ids
      var ids = vote
      vote_bits = sjcl.codec.bytes.toBits(ids)
      padding_bytes_length = 32 - 1 - 1 - ids.length
      break;
    default:
      throw new sjcl.exception.invalid("vote encoding not supported");
      break;
  }

  var flag_byte = Math.random() >= 0.5 ? 0x02 : 0x03;
  var flag_bits = sjcl.codec.bytes.toBits([flag_byte]);

  var type_bits = sjcl.codec.bytes.toBits([vote_encoding_type]);

  var suffix_bits = sjcl.codec.bytes.toBits([0x00]);

  var padding_bytes = [];
  for (i = 0; i < padding_bytes_length; i++)
    padding_bytes.push(0x00);
  var padding_bits = sjcl.codec.bytes.toBits(padding_bytes);

  var x_bits = sjcl.bitArray.concat(sjcl.bitArray.concat(sjcl.bitArray.concat(
      type_bits, vote_bits), padding_bits), suffix_bits);
  var x_bn = sjcl.bn.fromBits(x_bits);

  while (true) {
    var point_bits = sjcl.bitArray.concat(flag_bits, x_bn.toBits());

    try {
      var point = pointFromBits(point_bits);
      return point;
    } catch (err) {
      // increment
      x_bn.addM(1);
    }
  }
};

function blankToPoint() {
  return new sjcl.ecc.point(Curve);
}

function pointToVote(point) {
  var vote

  if (point.isIdentity)
    return {
      vote_encoding_type: vote_encoding_types.BLANK,
      vote: null
    };

  var x_bits = point.x.toBits();
  var vote_encoding_type = sjcl.bitArray.extract(x_bits, 0, 8);
  var vote_bits = sjcl.bitArray.bitSlice(x_bits, 8 * 1, 8 * 31);

  switch (vote_encoding_type) {
    case vote_encoding_types.TEXT:
      // vote is encoded as text
      vote = sjcl.codec.utf8String.fromBits(vote_bits);
      break;
    case vote_encoding_types.IDS:
      // vote is encoded as array of ids
      vote = sjcl.codec.bytes.fromBits(vote_bits)
      break;
    default:
      throw new sjcl.exception.corrupt("point does not have a valid vote encoding");
      break;
  }

  return {
    vote_encoding_type: vote_encoding_type,
    vote: vote
  };
}






//  voter use case methods
/**
 * Generates a pair of private public keys
 *
 * @return {(string, string)} An object with two fields, one for the private key and one for the public key
 */
function generateKeyPair() {
    var private_key = randomBN()
    var public_key = Curve.G.mult(private_key)

    return {
        private_key: sjcl.codec.hex.fromBits(private_key.toBits()),
        public_key: sjcl.codec.hex.fromBits(pointToBits(public_key, true))
    }
}

/**
 * Generates a SchnorrSignature on a paticular message
 *
 * @param {string}
 *            message The message to be signed.
 * @param {string}
 *            private_key_string The private key as a string
 * @return {string} The signature as a string
 */
function generateSchnorrSignature(message, private_key_string) {
    var private_key = sjcl.bn.fromBits(sjcl.codec.hex.toBits(private_key_string))
    var signature = SchnorrSignature.sign(message, private_key)

    return signature.toString()
}

/**
 * Verifies a SchnorrSignature on a paticular message
 *
 * @param {string}
 *            signature_string The signature as a string.
 * @param {string}
 *            message The message to be signed.
 * @param {string}
 *            public_key_string The signature verification key as a string
 * @return {boolean}
 */
function verifySchnorrSignature(signature_string, message, public_key_string) {
    var signature = SchnorrSignature.fromString(signature_string)
    var public_key = pointFromBits(sjcl.codec.hex.toBits(public_key_string))

    return signature.verify(public_key, message)
}

/**
 * Generates a random number
 * Used for generating a challenge
 *
 * @return {string} The number as a string
 */
function generateRandomNumber() {
    var challenge = randomBN()

    return sjcl.codec.hex.fromBits(challenge.toBits())
}

/**
 * Verifies a proof of empty cryptogram
 *
 * @param {string}
 *            proof_string The proof as a string (including commitment, challenge and response)
 * @param {string}
 *            empty_cryptogram_string The empty cryptogram encoded as string.
 * @param {string}
 *            encryption_key_string The encryption key as a string
 * @return {boolean}
 */
function verifyEmptyCrytogramProof(proof_string, empty_cryptogram_string, encryption_key_string) {
    var dlm_proof = DiscreteLogarithmMultipleProof.fromString(proof_string)
    var empty_cryptogram = ElGamalPointCryptogram.fromString(empty_cryptogram_string)
    var encryption_key = pointFromBits(sjcl.codec.hex.toBits(encryption_key_string))

    var generators = [Curve.G, encryption_key]
    var points = [empty_cryptogram.randomness_point, empty_cryptogram.ciphertext_point]

    return dlm_proof.verifyWithoutChallenge(generators, points)
}

/**
 * Encrypts the vote on top of the empty cryptogram
 *
 * @param {string}
 *            vote_text The text of the vote that should be encrypted
 * @param {string}
 *            empty_cryptogram_string The empty cryptogram encoded as string.
 * @param {string}
 *            encryption_key_string The encryption key as a string
 * @return {(string, string)} An object with two fields one for the vote cryptogram as string
 * and the second one as the randomness value used in the encryption as a string
 */
function encryptVote(vote_text, empty_cryptogram_string, encryption_key_string) {
    var vote_point = vote_text? textToPoint(vote_text) : new sjcl.ecc.point(Curve)
    var empty_cryptogram = ElGamalPointCryptogram.fromString(empty_cryptogram_string)

    var encryption_key = pointFromBits(sjcl.codec.hex.toBits(encryption_key_string))
    var randomness_bn = randomBN()
    var vote_cryptogram = ElGamalPointCryptogram.encrypt(vote_point, encryption_key, randomness_bn)
    vote_cryptogram.homomorphicallyAddCryptogram(empty_cryptogram)

    return {
        vote_cryptogram: vote_cryptogram.toString(),
        randomness_bn: sjcl.codec.hex.fromBits(randomness_bn.toBits())
    }
}

/**
 * Generates a discrete logarithm proof
 * Used for proving the correct encryption (proving the use of the empty cryptogram)
 *
 * @param {string}
 *            secret_string The private key of the proof as a string
 * @return {string} The proof as a string
 */
function generateDiscreteLogarithmProof(secret_string) {
    var secret = sjcl.bn.fromBits(sjcl.codec.hex.toBits(secret_string))

    var proof = DiscreteLogarithmProof.generate(Curve.G, secret)

    return proof.toString()
}