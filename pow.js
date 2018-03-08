const crypto=require('crypto')
var   request = require("request");
// Calculate a hash code from a binary buffer
var sha256= function(buffer) {
    var f = crypto.createHash('sha256');
    var h = f.update(buffer);
    return h.digest();
};

var serializeHeader = function (header) {
  var buffers = [];
  buffers.push (numberToInt32LE(header.version));
  buffers.push (hexaNotationToInt256LE(header.previousToken));
  buffers.push (hexaNotationToInt256LE(header.merkleRootHash));
  buffers.push (dateToInt32LE(header.time));
  buffers.push (numberToInt32LE(header.bits));
  buffers.push (numberToInt32LE(header.nonce));
  return Buffer.concat (buffers);
};
var numberToInt32LE = function (n) {
    var buffer = new Buffer(4);
    buffer.writeUInt32LE(n,0);
    return buffer;
};
var dateToInt32LE = function (date) {
    var time = date.getTime() / 1000; // remove milliseconds
    return numberToInt32LE(time);
};
var hexaNotationToInt256LE = function (hexa) {
    var bytes = new Array(32);
    for (var i = 0, j = 31, len = hexa.length; i < len; i+=2, j--) {
        bytes[j] = parseInt(hexa[i]+hexa[i+1],16);
    }
    return new Buffer(bytes);
};
Buffer.prototype.toReverseHexaNotation = function () {
    var hexa = "";
    for (var i = this.length-1; i >= 0; i--) {
        var digits =  this[i].toString(16);
        hexa += ("0" + digits).slice(-2); // Add "0" for single digit
    }
    return hexa;
};
var bigInt = require("big-integer");

var bitsToTarget = function (bits) {
    bits = bigInt(bits);
    var sign = bits.and(0x00800000).shiftRight(24).toJSNumber();
    var exponent = bits.and(0xFF000000).shiftRight(24).toJSNumber();
    var mantissa = bits.and(0x007FFFFF);
    var target = mantissa.times(Math.pow(-1,sign)).shiftLeft(8 * (exponent-3));
    return target;
}
var testProofOfWork = function (hashcode, target) {
    return hashcode.lesser(target);
}
// Header from block 0
var header = {
    version: 1,
    previousToken: '0000000000000000000000000000000000000000000000000000000000000000',
    merkleRootHash: '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
    time: new Date ("2009-01-03T18:15:05Z"),
    bits:  486604799,
    nonce: 2083236893
};

var target = bitsToTarget(header.bits);
console.log( 'Target=',target.toJSNumber() )
// Test hash code
var hashcode = sha256( sha256(serializeHeader(header)) ); // hash twice
console.log( 'The hash code=',hashcode.toReverseHexaNotation() );
// simimulate PoW

var tickStart = new Date();
console.log("Start Pow at ",tickStart.toLocaleString() );
header.nonce = 2083200000;
while(1) {
  var hashcode = sha256( sha256(serializeHeader(header)) ); // hash twice
  hashcode = bigInt(hashcode.toReverseHexaNotation(),16); // transform to big integer
  if( testProofOfWork(hashcode, target) ) break;
  header.nonce=header.nonce+1;
  if(header.bits > 2083236893) {
    console.log('Compute failure');
    break;
  }
}
var tickEnd = new Date();
var tick=(tickEnd-tickStart)/1000;
console.log( "  End Pow at ",tickEnd.toLocaleString(), 'Tick=',tick);
console.log( 'Expect=',(20832*tick)/60,'minutes' );
