'use strict';

var stratiscore = module.exports;

// module information
stratiscore.version = 'v' + require('./package.json').version;
stratiscore.versionGuard = function(version) {
  if (version !== undefined) {
    var message = 'More than one instance of bitcore-lib-stratis found. ' +
      'Please make sure to require bitcore-lib-stratis and check that submodules do' +
      ' not also include their own bitcore-lib-stratis dependency.';
    throw new Error(message);
  }
};
stratiscore.versionGuard(global._stratiscore);
global.__stratiscore = stratiscore.version;

// crypto
stratiscore.crypto = {};
stratiscore.crypto.BN = require('./lib/crypto/bn');
stratiscore.crypto.ECDSA = require('./lib/crypto/ecdsa');
stratiscore.crypto.Hash = require('./lib/crypto/hash');
stratiscore.crypto.Random = require('./lib/crypto/random');
stratiscore.crypto.Point = require('./lib/crypto/point');
stratiscore.crypto.Signature = require('./lib/crypto/signature');

// encoding
stratiscore.encoding = {};
stratiscore.encoding.Base58 = require('./lib/encoding/base58');
stratiscore.encoding.Base58Check = require('./lib/encoding/base58check');
stratiscore.encoding.BufferReader = require('./lib/encoding/bufferreader');
stratiscore.encoding.BufferWriter = require('./lib/encoding/bufferwriter');
stratiscore.encoding.Varint = require('./lib/encoding/varint');

// utilities
stratiscore.util = {};
stratiscore.util.buffer = require('./lib/util/buffer');
stratiscore.util.js = require('./lib/util/js');
stratiscore.util.preconditions = require('./lib/util/preconditions');

// errors thrown by the library
stratiscore.errors = require('./lib/errors');

// main bitcoin library
stratiscore.Address = require('./lib/address');
stratiscore.Block = require('./lib/block');
stratiscore.CirrusBlock = require('./lib/block/cirrusblock');
stratiscore.MerkleBlock = require('./lib/block/merkleblock');
stratiscore.BlockHeader = require('./lib/block/blockheader');
stratiscore.CirrusBlockHeader = require('./lib/block/cirrusblockheader');
stratiscore.HDPrivateKey = require('./lib/hdprivatekey.js');
stratiscore.HDPublicKey = require('./lib/hdpublickey.js');
stratiscore.Message = require('./lib/message');
stratiscore.Networks = require('./lib/networks');
stratiscore.Opcode = require('./lib/opcode');
stratiscore.PrivateKey = require('./lib/privatekey');
stratiscore.PublicKey = require('./lib/publickey');
stratiscore.Script = require('./lib/script');
stratiscore.Transaction = require('./lib/transaction');
stratiscore.URI = require('./lib/uri');
stratiscore.Unit = require('./lib/unit');

// dependencies, subject to change
stratiscore.deps = {};
stratiscore.deps.bnjs = require('bn.js');
stratiscore.deps.bs58 = require('bs58');
stratiscore.deps.Buffer = Buffer;
stratiscore.deps.elliptic = require('elliptic');
stratiscore.deps._ = require('lodash');

// Internal usage, exposed for testing/advanced tweaking
stratiscore.Transaction.sighash = require('./lib/transaction/sighash');
