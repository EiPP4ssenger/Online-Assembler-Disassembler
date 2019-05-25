
function hexByte(value) {
    value = value < 0 ? (value + 0x100) : (value);
    var str = '00' + value.toString(16).toUpperCase();
    return str.slice(-2);
};

function raw_hex(html_id, kst_result) {
    $(html_id).empty();
    for (var i = 0; i < kst_result.length; i++) {
        var ord = hexByte(kst_result[i]);
        if (ord == '00') ord = '<b>' + ord + '</b>';
        $(html_id).append(ord);
    }
}

function string_literal(html_id, kst_result) {
    $(html_id).empty();
    $(html_id).append('"');
    for (var i = 0; i < kst_result.length; i++)
        $(html_id).append("\\x" + hexByte(kst_result[i]));
    $(html_id).append('"');
}

function array_literal(html_id, kst_result) {
    $(html_id).empty();
    $(html_id).append('{ ');
    for (var i = 0; i < kst_result.length; i++) {
        var ord = "0x" + hexByte(kst_result[i]);
        if (i < kst_result.length-1) ord += ',';
        ord += ' ';
        $(html_id).append(ord);
    }
    $(html_id).append('}');
}

function disassembly(html_id, opcodes, asm_value, arch, endian, mode, offset) {

    $(html_id).empty();

    // disassemble (to get opcodes' length)
    var d = new cs.Capstone(arch, endian | mode);
    var instructions = d.disasm(opcodes, offset);
    d.close();

    var asm_split = asm_value.split(/[\n|;|\r|;\n]/)
    asm_split = asm_split.map(function (x) { return x.trim(); });   // remove trailing/front newlines
    asm_split = asm_split.filter(function(entry) { return /\S/.test(entry); });  // remove elements with only spaces
    asm_split = asm_split.filter(Boolean); // remove empty elements
    
    opcodes_spaces  = 0;
    address_spaces = 0;
    instructions.forEach(function (instr) {
        address_spaces = Math.max(("0x" + instr.address.toString(16) + ":").length, address_spaces);
        opcodes_spaces = Math.max(instr.bytes.length*2, opcodes_spaces);
    });

    var i = 0;
    asm_split.forEach(function (code) {

        var txt = '';

        if (code.match(/^.+:/)) {
            // if label
            label_only = code.replace(/(^.+:)\s+#.*/, "$1");   // extract label only
            txt += " ".repeat(address_spaces + opcodes_spaces+21 - label_only.length);
            txt += "<b>" + code + "</b><br>";
        } else {
            // if asm code
            var addr = instructions[i].address.toString(16);
            var opc  = instructions[i].bytes;
            opc = opc.map(function (x) { return hexByte(x); });
            opc = opc.join(' ');
            txt += "0x" + addr + ":" + " ".repeat(address_spaces - addr.length+3);
            txt += opc + " ".repeat(opcodes_spaces+15 - opc.length);
            txt += "<code class='hljs-asm'>" + code + "</code><br>";
            i++;
        }

        $(html_id).append(txt);

    });

    $('.hljs-asm').each(function(i, block) {
        hljs.highlightBlock(block);
    });

}