var crypto = require('crypto');
var secp256k1 = require('secp256k1');

var sha256 = function(buffer) { 
    var f = crypto.createHash("SHA256"); 
    var h = f.update(buffer);
    return h.digest(); 
};

var ripemd160 = function(buffer) { 
    var f = crypto.createHash("RIPEMD160"); 
    var h = f.update(buffer);
    return h.digest(); 
};


Buffer.prototype.toReverseHexaNotation = function () {
    var hexa = "";
    for (var i = this.length-1; i >= 0; i--) {
       var digits =  this[i].toString(16);
        hexa += ("0" + digits).slice(-2); // Add "0" for single digit
    }
    return hexa;     
};

var numberToInt8 = function (n) {
    return new Buffer([n]);
};

var numberToInt32LE = function (n) {
    var buffer = new Buffer(4);
    buffer.writeUInt32LE(n,0);
    return buffer;
};

var numberToInt64LE = function (n) {
   var buffer = new Buffer(8);
   buffer.writeUInt32LE(n % 0xFFFFFFFFFFFFFFFF, 0);
   buffer.writeUInt32LE(Math.floor(n / 0xFFFFFFFFFFFFFFFF), 4);
   return buffer;
};

var serializeAmount = function (amount) {
    return numberToInt64LE(amount * 100000000);
};

var hexaNotationToInt256LE = function (hexa) {
    var bytes = new Array(32);
    for (var i = 0, j = 31, len = hexa.length; i < len; i+=2, j--) {
        bytes[j] = parseInt(hexa[i]+hexa[i+1],16);
    }    
    return new Buffer(bytes);
};


var      OP_ADD         = 0x93;
var      OP_DUP         = 0x76;
var      OP_HASH160     = 0xa9;
var      OP_EQUALVERIFY = 0x88;
var      OP_CHECKSIG    = 0xac;


var serializeTransaction = function(tr) {
    var buffers = [];
    buffers.push(numberToInt32LE(tr.version));
    buffers.push(serializeInputs(tr.inputs));
    buffers.push(serializeOutputs(tr.outputs));
    buffers.push(numberToInt32LE(tr.lockTime));
    if (tr.hashType) 
        buffers.push(numberToInt32LE(Number(tr.hashType)));
    return Buffer.concat(buffers);
};

var serializeInputs = function (inputs) {
    var buffers = [];

    var inputsSize = inputs.length;
    buffers.push(numberToInt8(inputsSize));

    for (var i = 0; i < inputsSize; i++) {
        var input = inputs[i];

        buffers.push(hexaNotationToInt256LE(input.txid));
        buffers.push(numberToInt32LE(input.index));
        buffers.push(compileScript(input.script));
        buffers.push(numberToInt32LE(0xffffffff));
    }    
    return Buffer.concat (buffers);        
};

var serializeOutputs = function (outputs) {
    var buffers = [];

    var outputsSize = outputs.length;
    buffers.push(numberToInt8(outputsSize));
    for (var i = 0; i < outputsSize; i++) {
        var output = outputs[i];
        buffers.push(serializeAmount(output.amount));
        buffers.push(compileScript(output.script));
    }
    return Buffer.concat (buffers);        
};    

var compileScript = function(program) {
    var buffers = [];
    var bytes = 0;
    for (var i = 0, len = program.length; i < len; i++) {
        var code = program[i];
        var type = typeof(code);
        switch (type) {
            case 'number': 
                buffers.push(numberToInt8(code));
                bytes++;
                break;
            case 'string':
                var operand = new Buffer(code, 'hex');
                buffers.push(numberToInt8(operand.length));
                buffers.push(operand);
                bytes += operand.length + 1
                break;
        }        
    }
    buffers.unshift(numberToInt8(bytes));
    return Buffer.concat(buffers);
};

// A simple virtual machine to run a decoded P2SH (Pay to Script Hash) scripts



var runScript = function (program, stack, currentTransaction, currentInputIndex) {
    var operand;
    var operand1;
    var operand2;
    var ip = 0; // instruction pointer
    var last = program[ip++];
    while (ip <= last) {
        var instruction = program[ip++];

        switch (instruction) {
            case OP_DUP:
                operand = stack.pop();
                stack.push(operand);
                stack.push(operand);
                break;
            case OP_ADD:
                operand1 = stack.pop().readInt32LE();
                operand2 = stack.pop().readInt32LE();
                stack.push(numberToInt32LE(operand1 + operand2));
                break;
            case  OP_HASH160:
                operand = stack.pop();
                stack.push(ripemd160(sha256(operand)));
                break;

            case  OP_EQUALVERIFY:
                operand1 = stack.pop();
                operand2 = stack.pop();
                if (! operand1.compare(operand2) == 0) return false;
                break;

            case  OP_CHECKSIG:
                operand1 = stack.pop();
                operand2 = stack.pop();

                // operand 1 is Public Key
                var publicKey = operand1;

                // operand 2 contains hashType                
                var hashType = operand2[operand2.length-1]; //get last byte of signature

                // operand 2 contains DER Signature
                var signatureDER = operand2.slice(0,-1);
                var signature = secp256k1.signatureImport(signatureDER); // Decode a signature in DER format

                // recover signed transaction and hash of this transaction
                var copy = copyForSignature(currentTransaction, currentInputIndex, hashType);
                var buffer = serializeTransaction(copy);
                var hashcode = sha256 (sha256 (buffer));

                // Check signature
                if (! secp256k1.verify(hashcode, signature, publicKey)) return false;
                break;                
            default:
                var size = instruction;
                var data  = new Buffer(size);
                program.copy(data, 0, ip, size+ip);
                stack.push(data);
                ip += size;
                break;
        }
    }
    return true;
};

var SIGHASH_ALL    = "01";
var SIGHASH_NONE = "02";
var SIGHASH_SINGLE = "03";
var SIGHASH_ANYONECANPAY = "80";

// We create a previous transaction with an output
// We skip other data that are not required for validation

var previousTransaction = {
    version: 1,
    inputs: {}, // missing actual data here
    outputs: [
        {}, // missing output[0]
        {
            amount: 0.09212969, 
            script: [
                OP_DUP,
                OP_HASH160,
                '4586dd621917a93058ee904db1b7a43bfc05910a',
                OP_EQUALVERIFY,
                OP_CHECKSIG 
            ]
        }
    ],
    lockTime: 0
}; 

var transaction = {
   version: 1,
   inputs: [
        {
            txid: "14e5c51d3bc1cf0d29f2457d61fbf8d6567883e0711f9877795783d2105b50c9",
            index: 1,

            script: [
                  "3045" 
                + "0221"
                + "009eb819743dc981250daaaab0ad51e37ba47f7fb4ace61f6a69111850d6f29905"
                + "0220"
                + "6b6e59e1c002a4e35ba2be4d00366ea0f3e0b14c829907920705bce336ab2945" // signature
                +  SIGHASH_ALL,    // hashtype 

                "0275e9b1369179c24935337d597a06df0e388b53e8ac3f10ee426431d1a90c1b6e" // Public Key
            ]
        },
        { 
            txid: "5b7aeedc2e82c9646408ce0588d9f98d2107062e9291af0e9e6fa372b0d7d1fb",
            index: 1,

            script: [
                  "3045"
                + "0220"
                + "35a9e444883acaaae166d2ee1389272424ec7885f4210aaf118fee58b5683445"
                + "0221"
                + "00e40624a0df47943aa5ee63d8997dd36c5da44409ccc4dafcbfabc96a020d971c" // signature
                + SIGHASH_ALL,   // hashtype

                "033b18e24fb031dae396297516a54f3e46cc9902adfd1b8edea0d6a01dab0e027d" // Public Key
            ]
        }  
   ],
   outputs: [
        {
            amount: 0.05580569,
            script: [
                    OP_DUP, 
                    OP_HASH160, 
                    '4753945f3b34d6ca3fedcf41bf499c13d20bfec4',
                    OP_EQUALVERIFY,  
                    OP_CHECKSIG
            ],
        },
        {
            amount: 0.1,
            script: [
                    OP_DUP, 
                    OP_HASH160, 
                    '81a9e7d0ab008005d36c61563a178ad20a3a5224',
                    OP_EQUALVERIFY, 
                    OP_CHECKSIG
            ],
        }    
   ],    
   lockTime: 0
};


var dbtx = {};
dbtx["14e5c51d3bc1cf0d29f2457d61fbf8d6567883e0711f9877795783d2105b50c9"] = previousTransaction;
dbtx["9e9f1efee35b84bf71a4b741c19e1acc6a003f51ef8a7302a3dcd428b99791e4"] = transaction;

var copyForSignature = function(transaction, inputIndex, hashType) {
    var copy = Object.assign({}, transaction);

    var inputs = copy.inputs;
    for (var i = 0, len = inputs.length; i < len; i++) {
        inputs[i].script = []; // reset script to nothing
    }

    var currentInput = inputs[inputIndex];

    var previousTransaction =  dbtx[currentInput.txid];
    var previousOutput =previousTransaction.outputs[currentInput.index];

    currentInput.script = previousOutput.script;

    copy.hashType = hashType;
    return copy;
};

var validateInput = function (transaction, inputIndex) {
    var stack = [];

    var input = transaction.inputs[inputIndex];
    var previousTransaction =  dbtx[input.txid];
    var previousOutput =previousTransaction.outputs[input.index];

    var program1 = compileScript(input.script);
    var program2 = compileScript(previousOutput.script);

    var result = runScript (program1, stack, transaction, inputIndex);
    if (result) result = runScript (program2, stack, transaction, inputIndex);
    console.log(stack);
    return result;
};

var currentTransaction = transaction;
var currentInputIndex  = 0;
console.log(validateInput(currentTransaction, currentInputIndex));

