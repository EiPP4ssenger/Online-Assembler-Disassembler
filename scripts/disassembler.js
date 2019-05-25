
// ref: https://github.com/aquynh/capstone/blob/master/cstool/cstool.c#L11
var DISASM_CONSTANTS_CAPSTONE = [
    // ARM
    [
        // ENDIANS
        {
            'Little-Endian': cs.MODE_LITTLE_ENDIAN,
            'Big-Endian': cs.MODE_BIG_ENDIAN
        },
        // MODES
        {
            'ARM': cs.MODE_ARM,
            'THUMB': cs.MODE_THUMB,
            'ARM_v8': cs.MODE_ARM | cs.MODE_V8,
            'THUMB_v8': cs.MODE_THUMB | cs.MODE_V8,
            'THUMB_MCLASS': cs.MODE_THUMB | cs.MODE_MCLASS,
        }
    ],
    // ARM64
    [
        // ENDIANS
        {
            'Little-Endian': cs.MODE_LITTLE_ENDIAN,
            'Big-Endian': cs.MODE_BIG_ENDIAN
        },
        // MODES
        {
        }
    ],
    // MIPS
    [
        // ENDIANS
        {
            'Little-Endian': cs.MODE_LITTLE_ENDIAN,
            'Big-Endian': cs.MODE_BIG_ENDIAN
        },
        // MODES
        {
            'MIPS_X86': cs.MODE_MIPS32,
            'MIPS_X64': cs.MODE_MIPS64
        }
    ],
    // x86
    [
        // ENDIANS
        {
        },
        // MODES
        {
            '64-bit': cs.MODE_64,
            '32-bit': cs.MODE_32,
            '16-bit': cs.MODE_16
        }
    ],
    // PowerPC
    [
        // ENDIANS
        {
            'Little-Endian': cs.MODE_LITTLE_ENDIAN,
            'Big-Endian': cs.MODE_BIG_ENDIAN
        },
        // MODES
        {
            'PPC_64': cs.MODE_64
        }
    ],
    // SPARK
    [
        // ENDIANS
        {
            'Big-Endian': cs.MODE_BIG_ENDIAN
        },
        // MODES
        {
        }
    ],
    // SystemZ
    [
        // ENDIANS
        {
            'Big-Endian': cs.MODE_BIG_ENDIAN
        },
        // MODES
        {
        }
    ],
    // XCore
    [
        // ENDIANS
        {
            'Big-Endian': cs.MODE_BIG_ENDIAN
        },
        // MODES
        {
        }
    ]
];


function disasm_arch_fill(sel) {

    $('#disasm_mode').empty();
    $('#disasm_endianness').empty();

    var index = parseInt(sel.value);

    var endians = DISASM_CONSTANTS_CAPSTONE[index][0];
    var modes   = DISASM_CONSTANTS_CAPSTONE[index][1];

    for (var key in endians)
        $('#disasm_endianness').append('<option value="' + endians[key] + '">' + key + '</option>');
    
    for (var key in modes)
        $('#disasm_mode').append('<option value="' + modes[key] + '">' + key + '</option>');
}

function disasm_onClick() {
    
    // hide divs
    $('#disasm_err').attr('hidden', true);
    $('#disasm_output').attr('hidden', true);

    var arch = $('#disasm_arch').val();
    var endian = $('#disasm_endianness').val();
    var mode = $('#disasm_mode').val();
    var offset = parseInt($('#disasm_offset').val(), 16);

    var disasm_value = disasm_editor.getValue();
    if (!disasm_value) return;

    // try to capture input variations as much as possible
    // eq; transform `0x12, 0x13` (or any other input type) to basic `1213`
    var disasm_value_filter = disasm_value;
    disasm_value_filter = disasm_value_filter.replace(/\n/g, ''); // remove newlines
    disasm_value_filter = disasm_value_filter.replace(/0x/g, ''); // remove 0x
    disasm_value_filter = disasm_value_filter.replace(/\\x/g, ''); // remove \x
    disasm_value_filter = disasm_value_filter.replace(/[\s,]/g, ''); // remove any spaces or commas

    var opcodes = disasm_value_filter.match(/.{1,2}/g); // split hex-string into per-byte (2 chars)

    // convert hex-string into integer
    for (var i = 0; i < opcodes.length; i++)
        opcodes[i] = parseInt(opcodes[i], 16)

    var instructions = null;

    try{
        var cstone = new cs.Capstone(arch, endian | mode);
        cstone.option(cs.OPT_DETAIL, cs.OPT_ON);
        instructions = cstone.disasm(opcodes, offset);
        cstone.close();
    } catch (err) {
        $('#disasm_err').text(err);
        $('#disasm_err').attr('hidden', false);
        return;
    }

    if (!instructions.length) {
        $('#disasm_err').text('Capstone does not return data! Check again your architecture settings.');
        $('#disasm_err').attr('hidden', false);
        return;
    }

    var disasm_arr = [];
    var labels = new Set();

    instructions.forEach(function (instr) {

        var op_str = instr.op_str;

        // find branch
        if (instr.detail.groups.includes(cs.GRP_JUMP) || instr.detail.groups.includes(cs.GRP_CALL)) {
            var addr_match = op_str.match(/[^,]*0x[a-fA-F0-9]+/)[0];
            addr_match = addr_match.replace(/[^,]*0x/, '');
            labels.add(parseInt(addr_match, 16));
            op_str = 'loc_' + addr_match
        }

        disasm_arr.push([instr.address, instr.mnemonic + "\t" + op_str]);
    });

    // insert label for branch
    labels.forEach(function (addr) {
        for (var i = 0; i < disasm_arr.length; i++) {
            if (disasm_arr[i][0] == addr) {
                disasm_arr.splice(i, 0, [0, 'loc_' + addr.toString(16) + ':']);
                break;
            }
        }
    });

    // merge disassembly output
    var disasm_text = '';
    disasm_arr.forEach(function (code) {
        disasm_text += code[1] + "\n";
    });

    $('#disasm_output').attr('hidden', false);

    raw_hex('#disasm_raw_hex', opcodes);
    string_literal('#disasm_string_literal', opcodes);
    array_literal('#disasm_array_literal', opcodes);
    disassembly('#disasm_disassembly', opcodes, disasm_text, arch, endian, mode, offset);
}