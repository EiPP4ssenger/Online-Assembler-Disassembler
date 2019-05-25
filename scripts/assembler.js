
// ref: https://github.com/keystone-engine/keystone/blob/master/kstool/kstool.cpp#L151
var ASM_CONSTANTS_KEYSTONE = [
    // ARM
    [
        // ENDIANS
        {
            'Little-Endian': ks.MODE_LITTLE_ENDIAN,
            'Big-Endian': ks.MODE_BIG_ENDIAN
        },
        // MODES
        {
            'ARM': ks.MODE_ARM,
            'THUMB': ks.MODE_THUMB,
            'ARM_v8': ks.MODE_ARM | ks.MODE_V8,
            'THUMB_v8': ks.MODE_THUMB | ks.MODE_V8,
        }
    ],
    // ARM64
    [
        // ENDIANS
        {
            'Little-Endian': ks.MODE_LITTLE_ENDIAN
        },
        // MODES
        {
        }
    ],
    // MIPS
    [
        // ENDIANS
        {
            'Little-Endian': ks.MODE_LITTLE_ENDIAN,
            'Big-Endian': ks.MODE_BIG_ENDIAN
        },
        // MODES
        {
            'MIPS_X86': ks.MODE_MIPS32,
            'MIPS_X64': ks.MODE_MIPS64
        }
    ],
    // x86
    [
        // ENDIANS
        {
        },
        // MODES
        {
            '64-bit': ks.MODE_64,
            '32-bit': ks.MODE_32,
            '16-bit': ks.MODE_16
        }
    ],
    // PowerPC
    [
        // ENDIANS
        {
            'Little-Endian': ks.MODE_LITTLE_ENDIAN,
            'Big-Endian': ks.MODE_BIG_ENDIAN
        },
        // MODES
        {
            'PPC_32': ks.MODE_PPC32,
            'PPC_64': ks.MODE_PPC64
        }
    ],
    // SPARK
    [
        // ENDIANS
        {
            'Little-Endian': ks.MODE_LITTLE_ENDIAN,
            'Big-Endian': ks.MODE_BIG_ENDIAN
        },
        // MODES
        {
            'SPARC_32': ks.MODE_SPARC32,
            'SPARC_64': ks.MODE_SPARC64
        }
    ],
    // SystemZ
    [
        // ENDIANS
        {
            'Big-Endian': ks.MODE_BIG_ENDIAN
        },
        // MODES
        {
        }
    ],
];

function asm_arch_fill(sel) {

    $('#asm_mode').empty();
    $('#asm_endianness').empty();

    var index = parseInt(sel.value) - 1;

    var endians = ASM_CONSTANTS_KEYSTONE[index][0];
    var modes   = ASM_CONSTANTS_KEYSTONE[index][1];

    for (var key in endians)
        $('#asm_endianness').append('<option value="' + endians[key] + '">' + key + '</option>');
    
    for (var key in modes)
        $('#asm_mode').append('<option value="' + modes[key] + '">' + key + '</option>');
}

function asm_onClick() {
    
    // hide divs
    $('#asm_err').attr('hidden', true);
    $('#asm_output').attr('hidden', true);

    var arch = $('#asm_arch').val();
    var endian = $('#asm_endianness').val();
    var mode = $('#asm_mode').val();
    var offset = parseInt($('#asm_offset').val(), 16);

    // special case for PowerPC
    if (arch == ks.ARCH_PPC && endian == ks.MODE_LITTLE_ENDIAN && mode == ks.MODE_PPC32) {
        $("#asm_err").text("PowerPC PPC32 does not have little endian support!");
        $('#asm_err').attr('hidden', false);
        return;
    }
    
    var asm_value = asm_editor.getValue();
    if (!asm_value) return;

    var asm_value_filter = asm_value;
    asm_value_filter = asm_value_filter.replace(/.+\(\):\s*/g, '');  // remove function name, eq: `test():`
    asm_value_filter = asm_value_filter.replace(/#.*$/g, ''); // remove trailing comments (keystone can't handle it)

    var kst_result = null;
    try {
        var kst = new ks.Keystone(arch, endian | mode);
        kst_result = kst.asm(asm_value_filter, offset);
        kst.close();
    } catch (err) {
        $('#asm_err').text(err);
        $('#asm_err').attr('hidden', false);
        return;
    }

    if (!kst_result.length) {
        $('#asm_err').text('Keystone does not return data! Check again your architecture settings.');
        $('#asm_err').attr('hidden', false);
        return;
    }

    $('#asm_output').attr('hidden', false);

    // display value into UI
    raw_hex('#asm_raw_hex', kst_result);
    string_literal('#asm_string_literal', kst_result);
    array_literal('#asm_array_literal', kst_result);
    disassembly('#asm_disassembly', kst_result, asm_value, arch-1, endian, mode, offset);
}