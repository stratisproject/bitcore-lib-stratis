'use strict';

var _ = require('lodash');

var BN = require('../crypto/bn');
var BufferUtil = require('../util/buffer');
var BufferReader = require('../encoding/bufferreader');
var BufferWriter =  require('../encoding/bufferwriter');
var Hash = require('../crypto/hash');
var JSUtil = require('../util/js');
var $ = require('../util/preconditions');

var GENESIS_BITS = 0x1d00ffff;

/**
 * Instantiate a BlockHeader from a Buffer, JSON object, or Object with
 * the properties of the BlockHeader
 *
 * @param {*} - A Buffer, JSON string, or Object
 * @returns {CirrusBlockHeader} - An instance of block header
 * @constructor
 */
var CirrusBlockHeader = function CirrusBlockHeader(arg) {
  if (!(this instanceof CirrusBlockHeader)) {
    return new CirrusBlockHeader(arg);
  }

  var info = CirrusBlockHeader._from(arg);
  this.version = info.version;
  this.prevHash = info.prevHash;
  this.merkleRoot = info.merkleRoot;
  this.time = info.time;
  this.timestamp = info.time;
  this.bits = info.bits;
  this.nonce = info.nonce;
  this.signature = info.signature;
  this.hashStateRoot = info.hashStateRoot;
  this.receiptRoot = info.receiptRoot;
  this.logsBloom = info.logsBloom;

  if (info.hash) {
    $.checkState(
      this.hash === info.hash,
      'Argument object hash property does not match block hash.'
    );
  }

  return this;
};

/**
 * @param {*} - A Buffer, JSON string or Object
 * @returns {Object} - An object representing block header data
 * @throws {TypeError} - If the argument was not recognized
 * @private
 */
CirrusBlockHeader._from = function _from(arg) {
  var info = {};
  if (BufferUtil.isBuffer(arg)) {
    info = CirrusBlockHeader._fromBufferReader(BufferReader(arg));
  } else if (_.isObject(arg)) {
    info = CirrusBlockHeader._fromObject(arg);
  } else {
    throw new TypeError('Unrecognized argument for BlockHeader');
  }
  return info;
};

/**
 * @param {Object} - A JSON string
 * @returns {Object} - An object representing block header data
 * @private
 */
CirrusBlockHeader._fromObject = function _fromObject(data) {
  $.checkArgument(data, 'data is required');
  var prevHash = data.prevHash;
  var merkleRoot = data.merkleRoot;
  if (_.isString(data.prevHash)) {
    prevHash = BufferUtil.reverse(Buffer.from(data.prevHash, 'hex'));
  }
  if (_.isString(data.merkleRoot)) {
    merkleRoot = BufferUtil.reverse(Buffer.from(data.merkleRoot, 'hex'));
  }
  var info = {
    hash: data.hash,
    version: data.version,
    prevHash: prevHash,
    merkleRoot: merkleRoot,
    time: data.time,
    timestamp: data.time,
    bits: data.bits,
    nonce: data.nonce,
    signature: data.signature,
    hashStateRoot: data.hashStateRoot,
    receiptRoot: data.receiptRoot,
    logsBloom: data.logsBloom
  };
  return info;
};

/**
 * @param {Object} - A plain JavaScript object
 * @returns {CirrusBlockHeader} - An instance of block header
 */
CirrusBlockHeader.fromObject = function fromObject(obj) {
  var info = CirrusBlockHeader._fromObject(obj);
  return new CirrusBlockHeader(info);
};

/**
 * @param {Binary} - Raw block binary data or buffer
 * @returns {CirrusBlockHeader} - An instance of block header
 */
CirrusBlockHeader.fromRawBlock = function fromRawBlock(data) {
  if (!BufferUtil.isBuffer(data)) {
    data = Buffer.from(data, 'binary');
  }
  var br = BufferReader(data);
  br.pos = CirrusBlockHeader.Constants.START_OF_HEADER;
  var info = CirrusBlockHeader._fromBufferReader(br);
  return new CirrusBlockHeader(info);
};

/**
 * @param {Buffer} - A buffer of the block header
 * @returns {CirrusBlockHeader} - An instance of block header
 */
CirrusBlockHeader.fromBuffer = function fromBuffer(buf) {
  var info = CirrusBlockHeader._fromBufferReader(BufferReader(buf));
  return new CirrusBlockHeader(info);
};

/**
 * @param {string} - A hex encoded buffer of the block header
 * @returns {CirrusBlockHeader} - An instance of block header
 */
CirrusBlockHeader.fromString = function fromString(str) {
  var buf = Buffer.from(str, 'hex');
  return CirrusBlockHeader.fromBuffer(buf);
};

/**
 * @param {BufferReader} - A BufferReader of the block header
 * @returns {Object} - An object representing block header data
 * @private
 */
CirrusBlockHeader._fromBufferReader = function _fromBufferReader(br, extraByte = true) {
  var info = {};
  info.version = br.readInt32LE();
  info.prevHash = br.read(32);
  info.merkleRoot = br.read(32);
  info.time = br.readUInt32LE();
  info.bits = br.readUInt32LE();
  info.nonce = br.readUInt32LE();
  info.signature = br.readVarLengthBuffer();
  info.hashStateRoot = br.read(32);
  info.receiptRoot = br.read(32);
  info.logsBloom = br.read(256);
  
  return info;
};

/**
 * @param {BufferReader} - A BufferReader of the block header
 * @returns {CirrusBlockHeader} - An instance of block header
 */
CirrusBlockHeader.fromBufferReader = function fromBufferReader(br, extraByte) {
  var info = CirrusBlockHeader._fromBufferReader(br, extraByte);
  return new CirrusBlockHeader(info);
};

/**
 * @returns {Object} - A plain object of the BlockHeader
 */
CirrusBlockHeader.prototype.toObject = CirrusBlockHeader.prototype.toJSON = function toObject() {
  return {
    hash: this.hash,
    version: this.version,
    prevHash: BufferUtil.reverse(this.prevHash).toString('hex'),
    merkleRoot: BufferUtil.reverse(this.merkleRoot).toString('hex'),
    time: this.time,
    bits: this.bits,
    nonce: this.nonce,
    signature: this.signature,
    hashStateRoot: this.hashStateRoot,
    receiptRoot: this.receiptRoot,
    logsBloom: this.logsBloom
  };
};

/**
 * @returns {Buffer} - A Buffer of the BlockHeader
 */
CirrusBlockHeader.prototype.toBuffer = function toBuffer() {
  return this.toBufferWriter().concat();
};

/**
 * @returns {Buffer} - A Buffer of the BlockHeader containing only the data used for hashing.
 */
CirrusBlockHeader.prototype.toHashingBuffer = function toHashingBuffer() {
  var bw = new BufferWriter();
  bw.writeInt32LE(this.version);
  bw.write(this.prevHash);
  bw.write(this.merkleRoot);
  bw.writeUInt32LE(this.time);
  bw.writeUInt32LE(this.bits);
  bw.writeUInt32LE(this.nonce);
  bw.write(this.hashStateRoot);
  bw.write(this.receiptRoot);
  bw.write(this.logsBloom);
  return bw.concat();
}

/**
 * @returns {string} - A hex encoded string of the BlockHeader
 */
CirrusBlockHeader.prototype.toString = function toString() {
  return this.toBuffer().toString('hex');
};

/**
 * @param {BufferWriter} - An existing instance BufferWriter
 * @returns {BufferWriter} - An instance of BufferWriter representation of the BlockHeader
 */
CirrusBlockHeader.prototype.toBufferWriter = function toBufferWriter(bw) {
  if (!bw) {
    bw = new BufferWriter();
  }
  bw.writeInt32LE(this.version);
  bw.write(this.prevHash);
  bw.write(this.merkleRoot);
  bw.writeUInt32LE(this.time);
  bw.writeUInt32LE(this.bits);
  bw.writeUInt32LE(this.nonce);
  bw.writeVarintNum(this.signature.length)
  bw.write(this.signature);
  bw.write(this.hashStateRoot);
  bw.write(this.receiptRoot);
  bw.write(this.logsBloom);
  return bw;
};

/**
 * Returns the target difficulty for this block
 * @param {Number} bits
 * @returns {BN} An instance of BN with the decoded difficulty bits
 */
CirrusBlockHeader.prototype.getTargetDifficulty = function getTargetDifficulty(bits) {
  bits = bits || this.bits;

  var target = new BN(bits & 0xffffff);
  var mov = 8 * ((bits >>> 24) - 3);
  while (mov-- > 0) {
    target = target.mul(new BN(2));
  }
  return target;
};

/**
 * @link https://en.bitcoin.it/wiki/Difficulty
 * @return {Number}
 */
CirrusBlockHeader.prototype.getDifficulty = function getDifficulty() {
  var difficulty1TargetBN = this.getTargetDifficulty(GENESIS_BITS).mul(new BN(Math.pow(10, 8)));
  var currentTargetBN = this.getTargetDifficulty();

  var difficultyString = difficulty1TargetBN.div(currentTargetBN).toString(10);
  var decimalPos = difficultyString.length - 8;
  difficultyString = difficultyString.slice(0, decimalPos) + '.' + difficultyString.slice(decimalPos);

  return parseFloat(difficultyString);
};

/**
 * @returns {Buffer} - The little endian hash buffer of the header
 */
CirrusBlockHeader.prototype._getHash = function hash() {
  var buf = this.toHashingBuffer();
  return Hash.sha256sha256(buf);
};

var idProperty = {
  configurable: false,
  enumerable: true,
  /**
   * @returns {string} - The big endian hash buffer of the header
   */
  get: function() {
    if (!this._id) {
      this._id = BufferReader(this._getHash()).readReverse().toString('hex');
    }
    return this._id;
  },
  set: _.noop
};
Object.defineProperty(CirrusBlockHeader.prototype, 'id', idProperty);
Object.defineProperty(CirrusBlockHeader.prototype, 'hash', idProperty);

/**
 * @returns {Boolean} - If timestamp is not too far in the future
 */
CirrusBlockHeader.prototype.validTimestamp = function validTimestamp() {
  var currentTime = Math.round(new Date().getTime() / 1000);
  if (this.time > currentTime + CirrusBlockHeader.Constants.MAX_TIME_OFFSET) {
    return false;
  }
  return true;
};

/**
 * @returns {Boolean} - If the proof-of-work hash satisfies the target difficulty
 */
CirrusBlockHeader.prototype.validProofOfWork = function validProofOfWork() {
  var pow = new BN(this.id, 'hex');
  var target = this.getTargetDifficulty();

  if (pow.cmp(target) > 0) {
    return false;
  }
  return true;
};

/**
 * @returns {string} - A string formatted for the console
 */
CirrusBlockHeader.prototype.inspect = function inspect() {
  return '<BlockHeader ' + this.id + '>';
};

CirrusBlockHeader.Constants = {
  START_OF_HEADER: 8, // Start buffer position in raw block data
  MAX_TIME_OFFSET: 2 * 60 * 60, // The max a timestamp can be in the future
  LARGEST_HASH: new BN('10000000000000000000000000000000000000000000000000000000000000000', 'hex')
};

module.exports = CirrusBlockHeader;
