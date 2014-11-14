<?php
$idaPaths = array(    /* feel free to add yours here right in dropbox */
  'd:\ida',  // vos
  'Z:\Users\snk\ida64',
);
$askForAddingIdaPath = true;

echo "      ____  ____\n"
   . "   _ |___ \|___ \      Plus22 v0.3\n"
   . " _| |_ __) | __) |     IDA x64 .ASM listing -> x86 Hex-Rays\n"
   . "|_   _/ __/ / __/\n"
   . "  |_||_____|_____|     https://github.com/v0s/plus22\n"
   . "\n";

/* === Parse arguments ============================================================== */

$verboseMode = false;
$ecmAutoFixAll = false;

$args = $argv;
unset($args[0]);

foreach ($args as $i => $arg) {
  if ($arg[0] == '-') {
    foreach (str_split(substr($arg, 1)) as $ch) {
      if ($ch == 'v') {
        $verboseMode = true;
      } elseif ($ch == 'a') {
        $ecmAutoFixAll = true;
      }
    }
    unset($args[$i]);
  }
}
$args = array_values($args);

if (!isset($args[0])) {
  echo "USAGE: $argv[0] [-va] file_name\n"
     . "\n"
     . "  If file_name ends with '.asm', it will be interpreted as an ASM listing.\n"
     . "  Otherwise, it will be interpreted as x64 ELF/PE, and disassembled with IDA.\n"
     . "\n"
     . "  -v\tbe verbose and leave all temporary files\n"
     . "  -a\tAutoNop all lines with errors\n";
  exit(1);
}

$inputFileName = $args[0];

if (!file_exists($inputFileName)) {
  echo "[-] File $inputFileName doesn't exist\n";
  exit(1);
}

if (realpath(".") != realpath(dirname(__FILE__))) {
  $inputFileName = realpath($inputFileName);
  chdir(dirname(__FILE__));
}

$idaFoundPath = false;
foreach ($idaPaths as $path) {
  if (file_exists("$path/idaq.exe") && file_exists("$path/idaq64.exe")) {   // we will need both IDA and IDA64 later
    $idaFoundPath = $path;
    break;
  }
}

if ($askForAddingIdaPath && $idaFoundPath === false) {
  $selfContents = file_get_contents(__FILE__);

  echo "[-] Your IDA installation couldn't be found in \$idaPaths array.\n"
     . "    You can add it there by hand or have it auto-patched for you right now.\n"
     . "[?] Do you want to specify your IDA installation path now? [Y] ";

  if (strtolower(substr(fgets(STDIN), 0, 1)) != 'n') {
    while (true) {
      echo "[?] Enter IDA installation path: ";
      $path = trim(fgets(STDIN));
      if (file_exists("$path/idaq.exe") && file_exists("$path/idaq64.exe")) {
        break;
      }
      echo "[-] IDA not found. Please make sure both idaq.exe and idaq64.exe are there.\n";
    }
    $selfContents = preg_replace('#(\$idaPaths\s*=\s*array\(.*?)(,?\s*\)\s*;)#si', "\\1,\n  '" . str_replace(array("\\", "'"), array("\\\\\\\\", "\\\\'"), $path) . "'\\2", $selfContents, 1);    // REGEXP: add path to array
    file_put_contents(__FILE__, $selfContents);
    $idaFoundPath = $path;
    echo "[+] IDA found and your path has been patched into source.\n\n";
  } else {
    echo "[?] Do you want to stop this question from showing again? [n] ";
    if (strtolower(substr(fgets(STDIN), 0, 1)) == 'y') {
      $selfContents = preg_replace('#(\$askForAddingIdaPath\s*=\s*)true\s*;#i', '\1false;', $selfContents, 1);    // REGEXP: change var from true to false
      file_put_contents(__FILE__, $selfContents);
    }
  }
}

if ($idaFoundPath !== false) {
  $idaFoundPath = str_replace('/', '\\', $idaFoundPath);
}

/* === Figure out file names and types ============================================== */

$isBinaryGiven = (strtolower(substr($inputFileName, -4)) != ".asm");

if ($isBinaryGiven) {
  if ($idaFoundPath === false) {
    echo "[-] You have specified a binary, but your IDA installation couldn't be found.\n"
       . "    Modify \$idaPaths variable to include your IDA installation path.\n"
       . "    Or create ASM listing by hand (see README.md)\n";
    exit(1);
  }

  $inputBasename = basename($inputFileName);
  $magic = file_get_contents($inputFileName, null, null, 0, 4);
  if ($magic == "\x7fELF") {
    $inputOsType = "unix";
  } elseif (substr($magic, 0, 2) == "MZ") {
    $inputOsType = "windows";
  } else {
    echo "[-] You have specified a binary, but binary type is neither ELF nor PE.\n"
       . "Check your binary or create ASM listing by hand (see README.md)\n";
    exit(1);
  }
} else {
  $inputBasename = substr(basename($inputFileName), 0, -4);

  $f = file_get_contents($inputFileName);
  if (preg_match('#^[\t ]*;[\t ]*Format[\t ]*:[\t ]*(ELF|Portable[\t ]*executable)#mi', $f, $mt)) {   // REGEXP: detect input file format from IDA assembly listing
    $inputOsType = ($mt[1] == "ELF" ? "unix" : "windows");
  } else {
    echo "[-] You have specified a listing that doesn't contain a format specifier.\n";
    do {
      echo "[?] Is it an Elf (unix) or a Pe (windows)? [e,p] ";
      $input = strtolower(substr(fgets(STDIN), 0, 1));
    } while ($input != 'e' && $input != 'p');
    $inputOsType = ($input == 'e' ? "unix" : "windows");
  }
}

if (dirname($inputFileName) == '.') {
  $outputDirectory = "$inputBasename+22";
} else {
  $outputDirectory = dirname($inputFileName) . "/$inputBasename+22";
}
echo "[.] Output directory is '$outputDirectory'\n";

if (file_exists($outputDirectory)) {
  if (is_dir($outputDirectory)) {
    echo "[?] Output directory '$outputDirectory' already exists. Proceed? [Y] ";
    if (strtolower(substr(fgets(STDIN), 0, 1)) == 'n') {
      exit(1);
    }
  } else {
    echo "[?] Output directory '$outputDirectory' is occupied by a file. Delete file and proceed? [n] ";
    if (strtolower(substr(fgets(STDIN), 0, 1)) != 'y') {
      exit(1);
    }
    unlink($outputDirectory);
    mkdir($outputDirectory);
  }
} else {
  mkdir($outputDirectory);
}
echo "\n";

/* === Disassemble binary using IDA64 =============================================== */

if ($isBinaryGiven) {
  copy($inputFileName, "$outputDirectory/$inputBasename");
  $idbBasename = $inputBasename;
  if ($pos = strrpos($inputBasename, '.')) {
    $idbBasename = substr($inputBasename, 0, $pos);
  }
  echo "[*] Disassembling with IDA64\n";

  @unlink("$outputDirectory/$idbBasename.idb");
  @unlink("$outputDirectory/$idbBasename.i64");
  @unlink("$outputDirectory/$idbBasename.id0");
  @unlink("$outputDirectory/$idbBasename.id1");
  @unlink("$outputDirectory/$idbBasename.nam");
  @unlink("$outputDirectory/$idbBasename.til");

  copy("_misc/exporter.idc", "$outputDirectory/exporter.idc");
  copy($inputFileName, "$outputDirectory/$inputBasename");
  system("$idaFoundPath\\idaq64.exe -A -Sexporter.idc \"$outputDirectory/$inputBasename\"");
  if (! $verboseMode) {
    @unlink("$outputDirectory/exporter.idc");
    @unlink("$outputDirectory/$idbBasename.i64");
  }

  if (!file_exists("$outputDirectory/$idbBasename.asm")) {
    echo "[-] IDA64 failed to produce .asm file. Create ASM listing by hand (see README.md)\n";
    exit(1);
  }

  rename("$outputDirectory/$idbBasename.asm", "$outputDirectory/$inputBasename.asm");
} else {
  copy($inputFileName, "$outputDirectory/$inputBasename.asm");
}
echo "\n";

/* === x86ify ASM listing =========================================================== */

$f = file_get_contents("$outputDirectory/$inputBasename.asm");
$outputAsmFile = "$outputDirectory/$inputBasename+22.asm";

if (strpos($f, "BYTES: COLLAPSED FUNCTION") !== false) {
  echo "[-] COLLAPSED FUNCTION found. It's now required that you tell IDA to uncollapse all functions before producing ASM listing. To do this, use View -> Unhide All, and then re-export ASM. Or just specify your IDA path (see README.md) and let Plus22 do all the work.\n";
  exit(1);
}

$reservedWords = '(?:high|high32|highword|imagerel|length|lengthof|low|low32|lowword|lroffset|mask|offset|opattr|sectionrel|seg|short|size|sizeof|this|type|width|eq|ne|ge|gt|le|lt|mod|ptr|dup|page|subtitle|subttl|title|comment|if|ife|if1|if2|ifdif|ifdifi|ifidn|ifidni|ifb|ifnb|ifdef|ifndef|else|elseif|elseife|elseif1|elseif2|elseifdif|elseifdifi|elseifidn|elseifidni|elseifb|elseifnb|elseifdef|elseifndef|endif|for|irp|forc|irpc|repeat|rept|while|macro|exitm|endm|goto|purge|include|textequ|catstr|substr|instr|sizestr|db|dw|dd|df|dq|dt|struct|struc|union|typedef|record|comm|extern|extrn|externdef|public|proto|proc|endp|local|label|invoke|org|align|even|segment|ends|group|assume|alias|echo|end|equ|incbin|includelib|name|option|popcontext|pushcontext|addr|vararg|frame|stdcall|syscall|pascal|fortran|basic|fastcall)';
// IDA sometimes generates names that collide with reserved keywords

$origF = $f;

echo "[.] QWord -> DWord\n";
$f = preg_replace('#\bqword\b#mi', 'dword', $f);    // REGEXP: replace all isolated "qword" occurences with "dword" (matches "qword ptr", but not "qword_401000 dq 0")
preg_match_all('#^.+\b(qword_[0-9A-F]+)\b.*$#mi', $f, $mt, PREG_SET_ORDER);   // REGEXP: find all qword constants
foreach ($mt as $m) {
  if (preg_match('#\bxmm\d+\b#si', $m[0])) {    // REGEXP: check if there is an XMM operation on the constant
    $f = preg_replace('#^([\t ]*' . $m[1] . '[\t ])dq\b#mi', '\1!!!PLUS22_DQ_PROTECT!!!', $f);    // REGEXP: if so, protect it from becoming a dword
  }
}
$f = preg_replace('#\bdq\b#mi', 'dd', $f);    // REGEXP: replace all qword data with dword
$f = str_replace('!!!PLUS22_DQ_PROTECT!!!', 'dq', $f);    // REGEXP: restore protected qwords

$replCount = 0;
$f = explode("\n", $f);
foreach ($f as $lineNo => &$ln) {
  if (preg_match('#^(\s*(?:\w+\s+)?dd\s+)(.*?)((?:;.+)?)$#si', $ln, $mt)) {   // REGEXP: find a memory literal (var12 dd 01337DEADBEEFh)
    $ln = $mt[1] . preg_replace('#(F{8}|0{8})([0-9A-F]+h)\b#i', '\2', $mt[2], -1, $lReplCount) . $mt[3];    // REGEXP: replace sign-extended 32 bit constants (0FFFFFFFFFFF31337h -> 0FFF31337h)
    if (!$lReplCount) {
      $ln = $mt[1] . preg_replace('#0?+[0-9A-F]+([0-9A-F]{8}h\b)#i', '0\1', $mt[2], -1, $lReplCount) . $mt[3];   // REGEXP: replace other 64 bit constants by trimming (0C0457A47BABEh -> 07A47BABEh)
    }
    if ($lReplCount && $verboseMode) {
      echo "    QWord truncation: [" . ($lineNo + 1) . "] " . trim($mt[1] . $mt[2] . $mt[3]) . "\n";
    }
    $replCount += $lReplCount;
  } elseif (preg_match('#^(\s*(?:mov|cmp|and|or|xor)\s+\w+\s*,\s*)(.*?)((?:;.+)?)$#si', $ln, $mt)) {    // REGEXP: find memory operations with immediate arguments (mov rax, 01337DEADBEEFh)
    $ln = $mt[1] . preg_replace('#(F{8}|0{8})([0-9A-F]+h)\b#i', '\2', $mt[2], -1, $lReplCount) . $mt[3];
    if (!$lReplCount) {
      $ln = $mt[1] . preg_replace('#0?+[0-9A-F]+([0-9A-F]{8}h\b)#i', '0\1', $mt[2], -1, $lReplCount) . $mt[3];
    }
    if ($lReplCount > 0 && $verboseMode) {
      echo "    QWord truncation: [" . ($lineNo + 1) . "] " . trim($mt[1] . $mt[2] . $mt[3]) . "\n";
    }
    $replCount += $lReplCount;
  }
}
unset($ln);
$f = implode("\n", $f);
if ($replCount) {
  echo "[/!\\] Risky: 64-bit constants truncated to 32 bits ($replCount places)\n";
}

echo "[.] RBP -> EBP\n";
$f = preg_replace('#\br(bp|sp|si|di|ax|bx|cx|dx)\b#mi', 'e\1', $f);   // REGEXP: replace all 64 bit registers with 32 bit counterparts
if ($inputOsType == "unix") {
  $f = str_ireplace(array('r8d', 'r9d', 'r8b', 'r9b', 'r8w', 'r9w', 'r8', 'r9'), array('ebx', 'eax', 'bl', 'al', 'bx', 'ax', 'ebx', 'eax'), $f);    // REGEXP: replace r8, r9 with most rarely used 32 bit ones
} elseif ($inputOsType == "windows") {
  $f = str_ireplace(array('r8d', 'r9d', 'r8b', 'r9b', 'r8w', 'r9w', 'r8', 'r9'), array('esi', 'edi', 'esi', 'edi', 'esi', 'edi', 'esi', 'edi'), $f);
}
$f = preg_replace('#\br(\d+)d?\b#mi', 'ebx', $f);   // REGEXP: replace other 64-only registers with ebx
$f = preg_replace('#\br(\d+)w\b#mi', 'bx', $f);   // REGEXP: their word portions with bx
$f = preg_replace('#\br(\d+)b\b#mi', 'bl', $f);   // REGEXP: their byte portions with bl

echo "[.] Fixing directives\n";
$f = preg_replace('#(^[\t ]*\.intel_syntax noprefix)|use64#mi', '', $f);    // REGEXP: strip 64-related directives
$f = preg_replace('#align (\w+)#mi', 'db \1 dup (?)', $f);    // REGEXP: align misbehaves, replace with padding (align 8 -> db 8 dup (?))
$f = preg_replace('#^[\t ]*(' . $reservedWords . ')(?=[\t ]*=[\t ]*\w+[\t ]+ptr)#mi', 'KW_\1', $f);   // REGEXP: rename reserved-keyword (RK) local vars definition (proc = dword ptr -1Ch -> KW_proc)
$f = preg_replace('#^[\t ]*(\w+)[\t ]*=[\t ]*((?!xmmword|dword|word|byte)\w+)[\t ]+ptr.*$#mi', 'local \1:\2  ; \0', $f);    // REGEXP: replace strange typed local vars with "local" idiom (ipaddr = sin_addr ptr -24h -> local ipaddr:sin_addr)
$f = preg_replace('#(\[e[bs]p[\t ]*[+-][\t ]*)(' . $reservedWords . ')\b#mi', '\1KW_\2', $f);   // REGEXP: rename RK local vars usage ([ebp + proc] -> [ebp + KW_proc])
$f = preg_replace('#([\[+-])(' . $reservedWords . ')([\].])#mi', '\1KW_\2\3', $f);    // REGEXP: rename RK vars usage ([ebp+addr.port] -> [ebp+KW_addr.port])
$f = preg_replace('#^[\t ]*(' . $reservedWords . '):#mi', 'KW_\1:', $f);    // REGEXP: rename RK labels definition (proc: -> KW_proc:)
$f = preg_replace('#^[\t ]*(' . $reservedWords . ')(?=[\t ]+(db|dw|dd|dq)\b)#mi', 'KW_\1', $f);   // REGEXP: rename RK global vars definition (include db 'file.inc' -> KW_include db 'file.inc')
$f = preg_replace('#^[\t ]*(j\w+[\t ]+short[\t ]+)(' . $reservedWords . ')\b#mi', '\1KW_\2', $f);   // REGEXP: rename RK labels jump (jne short proc -> jne short KW_proc)
$f = preg_replace('#^[\t ]*assume.*$#mi', 'assume fs:nothing,gs:nothing', $f);    // REGEXP: assumes seem not to help anyway
$f = preg_replace('#^[\t ]*\.mmx#mi', ".xmm", $f);    // REGEXP: replace ".mmx" -> ".xmm"
$f = preg_replace('#\brva[\t ]+(\w|\$)#mi', 'offset \1', $f);   // REGEXP: replace "rva" -> "offset"
$f = str_replace('<?>', '<>', $f);    // REGEXP: replace IDA-style empty struc initializers with "<>"
$f = preg_replace('#^[\t ]*(loc_\w+):#mi', '\1 label near ', $f);   // REGEXP: replace local labels (loc_0401000: -> loc_0401000 label near)
$f = preg_replace('#offset[\t ]+\$LN\d+#mi', '0', $f);    // REGEXP: too lazy to understand what those $LN mean, just zero them
$f = preg_replace('#end[\t ]+_start\b#mi', 'end', $f);    // REGEXP: "end _start" -> "end"

echo "[.] Fixing instructions\n";
$f = preg_replace('#^[\t ]*nop.+$#mi', 'nop', $f);    // REGEXP: replace complex nops (nop dword ptr [eax + 0] -> nop)
$f = preg_replace('#^[\t ]*rep[\t ]+retn#mi', 'ret', $f);   // REGEXP: replace complex rets (rep retn -> ret)
$f = preg_replace('#^[\t ]*movsxd[\t ]+(e\w+)[\t ]*,[\t ]*((?:e\w+|(?:dword+[\t ]+ptr[\t ]*)?\[.+\])|(?:[c-g]s[\t ]*:[\t ]*)?dword_)#mi', 'mov \1, \2', $f);    // REGEXP: dafuq is that?
$f = preg_replace('#^[\t ]*movsxd[\t ]+(e\w+)[\t ]*,[\t ]*((?:\w+[\t ]+ptr[\t ]*)?\[.+\])#mi', 'movsx \1, \2', $f);   // REGEXP: i have no memory of this place.
$f = preg_replace('#^[\t ]*cdqe#mi', '', $f);   // REGEXP: strip "cdqe" instructions
$f = preg_replace('#^[\t ]*extrn[\t ]+([^\t\n :]++)(?!:)#mi', 'extrn \1:near', $f);   // REGEXP: replace externs (extrn fopen -> extrn fopen:near)
$f = preg_replace('#^[\t ]*(j\w+[\t ]+)short[\t ]+#mi', '\1', $f);    // REGEXP: strip short from jumps (jmp short loc_1 -> jmp loc_1)
$f = preg_replace('#^[\t ]*(j\w+[\t ]+)\$\+5#mi', '\1$+2', $f);   // REGEXP: jmp $+5 -> jmp $+2
$f = preg_replace('#^[\t ]*((?:(?!cvtsi2sd)\w+sd|movq)[\t ]+xmm\d+[\t ]*,[\t ]*)((?:dword+[\t ]+ptr[\t ]*)?)(\[)#mi', '\1qword ptr \3', $f);    // REGEXP: oh shit...
$f = preg_replace('#^[\t ]*((?:(?!cvtsi2sd)\w+sd|movq)[\t ]+)((?:(?:[c-g]s:)?dword+[\t ]+ptr[\t ]*)?)(\[.+\][\t ]*,[\t ]*xmm\d+)#mi', '\1qword ptr \3', $f);
$f = preg_replace('#^[\t ]*cqo#mi', 'cdq', $f);   // REGEXP: cqo -> cdq
$f = preg_replace('#^[\t ]*syscall#mi', 'int 80h', $f);   // REGEXP: syscall -> int 80h

if (preg_match('#rep[\t ]+stosq#mi', $f)) {   // REGEXP: find all "rep stosq" instructions
  echo "[/!\\] Risky: Fixing rep stosq -> add ecx, ecx ; rep stosd\n";
  $f = preg_replace('#^[\t ]*rep[\t ]+stosq#mi', "add ecx, ecx\nrep stosd", $f);    // REGEXP: replace them with "add ecx, ecx / rep stosd"
  $origF = preg_replace('#^[\t ]*rep[\t ]+stosq#mi', "\n" . '\0', $origF);
}
if (preg_match('#rep[\t ]+movsq#mi', $f)) {   // REGEXP: same with movsq
  echo "[/!\\] Risky: Fixing rep movsq -> add ecx, ecx ; rep movsd\n";
  $f = preg_replace('#^[\t ]*rep[\t ]+movsq#mi', "add ecx, ecx\nrep movsd", $f);
  $origF = preg_replace('#^[\t ]*rep[\t ]+movsq#mi', "\n" . '\0', $origF);
}

if (preg_match('#setn?z[\t ]+(sil|dil|spl|bpl)#mi', $f)) {    // REGEXP: find all "setnz sil"
  $f = preg_replace('#^[\t ]*(setn?z)[\t ]+(sil|dil|spl|bpl)#mi', "xchg ax, \\2\n\\1 al\nxchg ax, \\2", $f);    // REGEXP: replace them with "xchg ax, si / setnz al / xchg ax, si"
  $origF = preg_replace('#^[\t ]*(setn?z)[\t ]+(sil|dil|spl|bpl)#mi', "\n\\0\n", $origF);
}

function replace_sil_with_unused_xchg($mt) {
  $otherPart = $mt[1] . $mt[3];
  $found = false;
  foreach (array('ax' => "a", 'bx' => "b", 'cx' => "c", 'dx' => "d") as $wreg => $regp) {
    if (!strstr($otherPart, $wreg) && !strstr($otherPart, $regp . "l") && !strstr($otherPart, $regp . "h")) {
      $found = true;
      break;
    }
  }
  if (! $found) {
    return "\n" . $mt[0] . "\n";
  }
  return "xchg " . $wreg . ", " . $mt[2] . "\n"
       . $mt[1] . $regp . "l" . $mt[3] . "\n"
       . "xchg " . $wreg . ", " . $mt[2];
}

if (preg_match('#(mov|cmp|and|or|xor)[\t ]+(sil|dil|spl|bpl)#mi', $f)) {    // REGEXP: find all "mov sil, ..."
  $f = preg_replace_callback('#^[\t ]*(mov|cmp|and|or|xor[\t ]+)(sil|dil|spl|bpl)(.*?)$#mi', 'replace_sil_with_unused_xchg', $f);   // REGEXP: replace them with unused register xchg construction
  $origF = preg_replace('#^[\t ]*(mov|cmp|and|or|xor[\t ]+)(sil|dil|spl|bpl)(.*?)$#mi', "\n\\0\n", $origF);
}

if (preg_match('#(mov|cmp|and|or|xor)[\t ]+(.+?),[\t ]*(sil|dil|spl|bpl)#mi', $f)) {    // REGEXP: find all "mov ..., sil"
  $f = preg_replace_callback('#^[\t ]*(mov|cmp|and|or|xor[\t ]+.+?,[\t ]*)(sil|dil|spl|bpl)(.*?)$#mi', 'replace_sil_with_unused_xchg', $f);
  $origF = preg_replace('#^[\t ]*(mov|cmp|and|or|xor)[\t ]+(.+?),[\t ]*(sil|dil|spl|bpl)#mi', "\n\\0\n", $origF);
}

if (preg_match('#\b(spl|bpl|sil|dil)\b#mi', $f)) {
  echo "[/!\\] Risky: Fixing x64 one-byte registers SIL -> SI\n";
  $f = preg_replace('#\b(sp|bp|si|di)l\b#mi', '\1', $f);    // REGEXP: replace "sil" -> "si"
}

echo "[.] Renaming address-derived names (sub_XXXXXXX)\n";
$f = preg_replace('#\b(sub_|off_|unk_|byte_|word_|dword_|qword_|loc_|algn_|stru_)#mie', "strtoupper(substr('$1', 0, 1)) . substr('$1', 1)", $f);    // REGEXP: capitalize address-derived names (sub_0401000 -> Sub_0401000)

echo "[+] Convertion finished, output file is $outputAsmFile\n\n";

/* === Restore function types from TILs ============================================= */

echo "[.] Training neural networks using genetic algorithms\n";
$idaTilDb = unserialize(gzuncompress(file_get_contents("_misc/functype.db")));    // this database of function types was converted from IDA *.til files
echo "[.] Reticulating Kasinski's quaternions\n";

$tilsToLoad = array();
$typesToApply = array();

preg_match_all('#extrn[\t ]+(\w+)#mi', $f, $mt);    // REGEXP: find all import definitions
$imports = $mt[1];
$definedImports = array();
foreach ($imports as $imp) {
  $imp = ltrim(str_replace('_imp_', '', $imp), "_");
  $definedImports[$imp] = true;
}
preg_match_all('#^[\t ]*(\w+)[\t ]+proc\b#mi', $f, $mt);    // REGEXP: find all function definitions
$definedFuncs = array_flip($mt[1]);

if ($inputOsType == "unix") {
  $tilRegMap = array("<RETREG>" => "<eax>", "<ARG1>" => "<edi>", "<ARG2>" => "<esi>", "<ARG3>" => "<edx>", "<ARG4>" => "<ecx>", "<ARG5>" => "<ebx>", "<ARG6>" => "<eax>",
                     "<XRETREG>" => "<xmm0>", "<XARG1>" => "<xmm0>", "<XARG2>" => "<xmm1>", "<XARG3>" => "<xmm2>", "<XARG4>" => "<xmm3>", "<XARG5>" => "<xmm4>", "<XARG6>" => "<xmm5>", "<XARG7>" => "<xmm6>", "<XARG8>" => "<xmm7>");
} elseif ($inputOsType == "windows") {
  $tilRegMap = array("<RETREG>" => "<eax>", "<ARG1>" => "<ecx>", "<ARG2>" => "<edx>", "<ARG3>" => "<esi>", "<ARG4>" => "<edi>", "<ARG5>" => "", "<ARG6>" => "",
                     "<XRETREG>" => "<xmm0>", "<XARG1>" => "<xmm0>", "<XARG2>" => "<xmm1>", "<XARG3>" => "<xmm2>", "<XARG4>" => "<xmm3>", "<XARG5>" => "", "<XARG6>" => "", "<XARG7>" => "", "<XARG8>" => "");
}

$restoredByTil = 0;

foreach ($definedFuncs as $imp => $nul) {
  if (!isset($definedImports[ltrim(str_replace('_imp_', '', $imp), "_")])) {
    continue;
  }

  $candidateWeights = array();    // we will find the best candidate based on TIL and function name
  if (isset($idaTilDb["_$imp"])) {
    $candidateWeights["_$imp"] = $idaTilDb["_$imp"][0];
  }
  if (isset($idaTilDb[$imp])) {
    $candidateWeights[$imp] = $idaTilDb[$imp][0] * 0.9;
  }
  if ($imp[0] == '_' && isset($idaTilDb[substr($imp, 1)])) {
    $candidateWeights[substr($imp, 1)] = $idaTilDb[substr($imp, 1)][0] * 0.8;
  }
  if (empty($candidateWeights)) {   // failed to find a candidate? try case-insensitive
    $limp = strtolower($imp);
    if (isset($idaTilDb["_$limp"])) {
      $candidateWeights["_$limp"] = $idaTilDb["_$limp"][0];
    }
    if (isset($idaTilDb[$limp])) {
      $candidateWeights[$limp] = $idaTilDb[$limp][0] * 0.9;
    }
    if ($limp[0] == '_' && isset($idaTilDb[substr($limp, 1)])) {
      $candidateWeights[substr($limp, 1)] = $idaTilDb[substr($limp, 1)][0] * 0.8;
    }
  }

  if (!empty($candidateWeights)) {
    $dimp = array_search(max($candidateWeights), $candidateWeights);
    $til = $idaTilDb[$dimp][1];
    $type = $idaTilDb[$dimp][2];
    $numArgs = $idaTilDb[$dimp][3];

    $type = str_replace(array_keys($tilRegMap), array_values($tilRegMap), $type);

    $tilsToLoad[$til] = true;
    $typesToApply[$imp] = array($type, $numArgs);
    $typesToApply["_$imp"] = & $typesToApply[$imp];
    if ($imp[0] == '_') {
      $typesToApply[substr($imp, 1)] = & $typesToApply[$imp];
    }
    if ($verboseMode) {
      echo "    TIL $til: $imp -> $type\n";
    }
    $restoredByTil++;
  }
}

/* === Restore function types from guessing B-) ===================================== */

echo "[.] Balancing red-black trees using Gauss - Dijkstra heuristics\n";

if ($inputOsType == "unix") {
  $argPregs = array(    // regexps to detect registers in order they are used in x64 calling convention
    '#\b(rdi|edi|di|dil)\b#s',
    '#\b(rsi|esi|si|sil)\b#s',
    '#\b(rdx|edx|dx|dl|dh)\b#s',
    '#\b(rcx|ecx|cx|cl|ch)\b#s',
    '#\b(r8|r8d|r8b)\b#s',
    '#\b(r9|r9d|r9b)\b#s',
  );
  $argX86Regs = array("edi", "esi", "edx", "ecx", "ebx", "eax");
  $xargPregs = array('#\bxmm0\b#s', '#\bxmm1\b#s', '#\bxmm2\b#s', '#\bxmm3\b#s', '#\bxmm4\b#s', '#\bxmm5\b#s', '#\bxmm6\b#s', '#\bxmm7\b#s');
  $xargXmmRegs = array("xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7");
} elseif ($inputOsType == "windows") {
  $argPregs = array(
    '#\b(rcx|ecx|cx|cl|ch)\b#s',
    '#\b(rdx|edx|dx|dl|dh)\b#s',
    '#\b(r8|r8d|r8b)\b#s',
    '#\b(r9|r9d|r9b)\b#s',
  );
  $argX86Regs = array("ecx", "edx", "esi", "edi");
  $xargPregs = array('#\bxmm0\b#s', '#\bxmm1\b#s', '#\bxmm2\b#s', '#\bxmm3\b#s');
  $xargXmmRegs = array("xmm0", "xmm1", "xmm2", "xmm3");
}

$origF = explode("\n", $origF);
$funcArgCount = array();

foreach ($origF as $i => $ln) {
  $ln = trim($ln);
  if (preg_match('#^call[\t ]+(\w+)#mi', $ln, $mt)) {   // REGEXP: find a function call
    $funcName = $mt[1];
    $funcRegs = $funcXmmRegs = array();

    if (substr($funcName, 0, 4) == "sub_") {
      $funcName[0] = 'S';   // in $origF, we didn't capitalize address-derived names
    }

    if (!isset($definedFuncs[$funcName])) {
      if ($verboseMode) {
        echo "    guess: '$funcName' is not a function\n";
      }
      continue;
    }

    for ($li = $i - 1; $li >= 0; $li--) {
      $ln = trim($origF[$li]);
      if (!preg_match('#^(lea|mov\w*|xor)[\t ](.+?),(.+)$#mi', $ln, $mt)) {   // REGEXP: does line contain lea/mov/xor instruction?
        break;
      }

      if ($mt[1] == "xor") {
        continue;
      }

      $wrPart = $mt[2];
      $rdPart = $mt[3];
      foreach ($argPregs as $regI => $argPreg) {
        if (isset($funcRegs[$regI])) {
          if ($funcRegs[$regI] == "rd") {
            break;
          } elseif ($funcRegs[$regI] == "wr") {
            continue;
          }
        }
        if (preg_match($argPreg, $wrPart)) {
          $funcRegs[$regI] = "wr";
        } elseif (preg_match($argPreg, $rdPart)) {
          $funcRegs[$regI] = "rd";
        }
      }
      foreach ($xargPregs as $xregI => $xargPreg) {
        if (isset($funcXmmRegs[$xregI])) {
          if ($funcXmmRegs[$xregI] == "rd") {
            break;
          } elseif ($funcXmmRegs[$xregI] == "wr") {
            continue;
          }
        }
        if (preg_match($xargPreg, $wrPart)) {
          $funcXmmRegs[$xregI] = "wr";
        } elseif (preg_match($xargPreg, $rdPart)) {
          $funcXmmRegs[$xregI] = "rd";
        }
      }
    }

    $returnsXmm = false;
    for ($li = $i + 1; $li <= $i + 3; $li++) {
      if (strpos($origF[$li], "xmm0") !== false) {
        $returnsXmm = true;
        break;
      }
    }

    for ($numArgs = 0; $numArgs < count($argPregs); $numArgs++) {
      if (!isset($funcRegs[$numArgs]) || $funcRegs[$numArgs] == "rd") {
        break;
      }
    }
    for ($numXargs = 0; $numXargs < count($xargPregs); $numXargs++) {
      if (!isset($funcXmmRegs[$numXargs]) || $funcXmmRegs[$numXargs] == "rd") {
        break;
      }
    }

    if (!isset($funcArgCount[$funcName])) {
      $funcArgCount[$funcName] = array('x86args' => 0, 'xmmArgs' => 0, 'returnsXmm' => $returnsXmm);
    }
    if ($funcArgCount[$funcName]['x86args'] < $numArgs) {   // extend argument number of TIL data
      $funcArgCount[$funcName]['x86args'] = $numArgs;
    }
    if ($funcArgCount[$funcName]['xmmArgs'] < $numXargs) {
      $funcArgCount[$funcName]['xmmArgs'] = $numXargs;
    }
  }
}

$restoredByGuessing = 0;

foreach ($funcArgCount as $funcName => $numArgs) {
  $xregI = 0;
  if (isset($typesToApply[$funcName])) {    // have a TIL-defined type
    if ($typesToApply[$funcName][1] === false) {   // TIL-defined type doesn't have variadic arguments? skip.
      continue;
    } else {
      $type = $typesToApply[$funcName][0];
      $type = substr($type, 0, -2);   // cut trailing ");"
      $regI = $typesToApply[$funcName][1];
    }
  } else {
    if ($numArgs['returnsXmm']) {
      $type = "double __usercall $funcName<xmm0>(";
    } else {
      $type = "_DWORD __usercall $funcName<eax>(";
    }
    $regI = 0;
  }

  for (; $xregI < $numArgs['xmmArgs']; $xregI++) {
    if ($xregI + $regI > 0) {
      $type .= ", ";
    }
    $type .= "double <" . $xargXmmRegs[$xregI] . ">";
  }

  for (; $regI < $numArgs['x86args']; $regI++) {
    if ($xregI + $regI > 0) {
      $type .= ", ";
    }
    $type .= "_DWORD <" . $argX86Regs[$regI] . ">";
  }
  $type .= ");";

  $typesToApply[$funcName] = array($type, false);
  $restoredByGuessing++;
  if ($verboseMode) {
    echo "    GUESS: $funcName -> $type\n";
  }
}

$idc = "#include <idc.idc>\n"
     . "\n"
     . "static main() {\n"
     . "  Wait();\n"
     . "  \n";
foreach ($tilsToLoad as $til => $nul) {
  $idc .= "  LoadTil(\"$til\");\n";
}
$idc .= "  \n";
foreach ($typesToApply as $func => $type) {
  $idc .= "  SetType(LocByName(\"$func\"), \"$type[0]\");\n";
}

if (preg_match('#^[\t ]*(?:mov|lea)\s+edi,\s*(?:offset\s+)?(\w+)\s*(?:;.*)?$\s*^[\t ]*call\s+___libc_start_main#mi', $f, $mt)) {    // REGEXP: find main function from libc entry point
  $foundMain = $mt[1];
  $idc .= "\n"
        . "  auto mainEa = LocByName(\"$foundMain\");\n"
        . "  MakeName(mainEa, \"main\");\n"
        . "  SetType(mainEa, \"int __usercall main<eax>(int argc<edi>, char ** argv<esi>, char ** environ<edx>);\");\n"
        . "  Jump(mainEa);\n";
  $restoredByGuessing++;
}

$idc .= "\n"
      . "  auto exc;\n"
      . "  try {\n"
      . "    initOrigInstr();\n"
      . "  } catch (exc) {}\n";
$idc .= "\n"
      . "  if (Batch(0)) {\n"
      . "    Exit(0);\n"
      . "  }\n"
      . "}\n"
      . "\n";

file_put_contents("$outputDirectory/$inputBasename+22.idc", $idc);
echo "[+] Created IDC with function types ($restoredByTil detected, $restoredByGuessing guessed)\n\n";

/* === Build .asm with JWasm and fix errors ========================================= */

if ($inputOsType == "unix") {
  $outputFormat = "-elf";
} elseif ($inputOsType == "windows") {
  $outputFormat = "-coff";
}
$buildCmd = "_misc\\jwasm $outputFormat -fp3 -Fwnul -W1 -q -e500 \"-Fl$outputDirectory/$inputBasename+22.lst\" \"-Fo$outputDirectory/$inputBasename+22.obj\" \"$outputAsmFile\"";
/*
 *  -fp3    enable most FPU instructions
 *  -Fwnul  log errors to /dev/null
 *  -W1     lower warning level
 *  -q      don't display banner
 *  -e500   raise error limit to 500
 *  -Fl     create an .lst to map addresses
 *  -Fo     output file
 */
file_put_contents("$outputDirectory/build.cmd", $buildCmd);

$ecmHelpShown = false;
$ecmAutoFixCodes = array();
$ecmFixMode = "nop";

$lastOutput = false;

while (true) {
  echo "[*] Building... `$outputDirectory\\build.cmd`\n\n";
  file_put_contents($outputAsmFile, $f);
  @unlink("$outputDirectory/$inputBasename+22.obj");
  @unlink("$outputDirectory/$inputBasename+22.lst");
  unset($output);
  exec($buildCmd, $output, $retVal);

  if ($output === $lastOutput) {
    $ecmAutoFixAll = false;
  }
  $lastOutput = $output;

  $buildErrMsg = false;
  if ($retVal != 0) {
    $buildErrMsg = "There were errors during compilation. They need fixing to build the binary.";
  } elseif (!file_exists("$outputDirectory/$inputBasename+22.obj")) {
    $buildErrMsg = "JWasm failed to produce .obj file.";
  }

  if ($verboseMode || $buildErrMsg !== false) {
    echo implode("\n", $output) . "\n\n";
  }

  if ($buildErrMsg === false) {
    break;
  }

  $f = explode("\n", $f);

  if (! $ecmHelpShown && ! $ecmAutoFixAll) {
    echo "===========================================\n"
       . "|      /!\\ Error correction mode /!\\      |\n"
       . "===========================================\n"
       . "\n";

    echo "[!] $buildErrMsg\n"
       . "    Your choices:\n"
       . "      A - Autonop All errors (most easy way :-)\n"
       . "      C - nop all errors with current error Code\n"
       . "      O - nop Only One current error\n"
       . "      M - switch fixing Mode (nop/comment/purge, current: $ecmFixMode)\n"
       . "      E - edit the line\n"
       . "      R - Re-read and Rebuild $outputAsmFile (you have to fix it by hand)\n"
       . "      Q - Quit\n"
       . "\n";

    $ecmHelpShown = true;
  }

  $errorsFound = false;

  foreach ($output as $line) {
    if (!preg_match('#\.asm\((\d+)\) : Error (\w+): (.+)#s', $line, $mt)) {   // REGEXP: find error line number, code and description
      continue;
    }
    $lineNo = $mt[1];
    $errCode = $mt[2];
    $errStr = $mt[3];

    if (! $ecmAutoFixAll && !isset($ecmAutoFixCodes[$errCode])) {
      for ($i = max(1, $lineNo - 2); $i < max(1, $lineNo - 2) + 5; $i++) {
        printf("%s %7d | %s\t%s\n", $i == $lineNo ? "=>" : "  ", $i, trim($f[$i - 1]), $i == $lineNo ? "<=" : "  ");    // display error line and context (+-2 lines)
      }
      echo "\n[!] Error $errCode on line $lineNo: $errStr\n";
      do {
        echo "[?] Fix = $ecmFixMode. Your choice? [a,c,o,m,e,r,q] ";
        $input = strtolower(substr(fgets(STDIN), 0, 1));

        if ($input == "m") {
          if ($ecmFixMode == "nop") {
            $ecmFixMode = "comment";
          } elseif ($ecmFixMode == "comment") {
            $ecmFixMode = "purge";
          } elseif ($ecmFixMode == "purge") {
            $ecmFixMode = "nop";
          }
        }
      } while (!strstr("acoerq", $input));
      echo "\n";

      if ($input == 'q') {
        echo "[-] Giving up trying to fix errors.\n"
           . "    You can still fix $outputAsmFile by hand, and build by running:\n"
           . "    `$outputDirectory\\build.cmd`\n"
           . "    Then use $inputBasename+22.idc to restore types\n";
        exit(1);
      } elseif ($input == 'e') {
        echo "[?] $lineNo: ";
        $editedLine = trim(fgets(STDIN));
        $f[$lineNo - 1] = $editedLine;
      } elseif ($input == 'r') {
        $f = file_get_contents($outputAsmFile);
        continue(2);
      } elseif ($input == 'a') {
        $ecmAutoFixAll = true;
      } elseif ($input == 'c') {
        $ecmAutoFixCodes[$errCode] = true;
      }
    }

    if ($ecmFixMode == "nop") {
      $f[$lineNo - 1] = "nop";
    } elseif ($ecmFixMode == "comment") {
      $f[$lineNo - 1] = "; " . $f[$lineNo - 1];
    } elseif ($ecmFixMode == "purge") {
      $f[$lineNo - 1] = " ";
    }
    $errorsFound = true;
    if (! $ecmAutoFixAll && !isset($ecmAutoFixCodes[$errCode])) {
      file_put_contents($outputAsmFile, implode("\n", $f));
    }
  }

  if (! $errorsFound) {
    echo "[!] There were no errors in JWasm output, but it still didn't produce .obj file.\n";
    do {
      echo "[?] Do you want to Re-read and rebuild $outputAsmFile or to Quit? [r,q] ";
      $input = strtolower(substr(fgets(STDIN), 0, 1));
    } while (!strstr("rq", $input));
    echo "\n";

    if ($input == 'q') {
      echo "[-] Giving up trying to fix errors.\n"
         . "    You can still fix $outputAsmFile by hand, and build by running:\n"
         . "    `$outputDirectory\\build.cmd`\n"
         . "    Then use $inputBasename+22.idc to restore types\n";
      exit(1);
    }

    if ($input == 'r') {
      $f = file_get_contents($outputAsmFile);
      continue;
    }
  }

  $f = implode("\n", $f);
}

echo "[+] Build successful\n\n";
if (! $verboseMode) {
  @unlink("$outputDirectory/$inputBasename+22.asm");
  @unlink("$outputDirectory/build.cmd");
  if ($isBinaryGiven) {
    @unlink("$outputDirectory/$inputBasename.asm");
  }
}

/* === Map .obj addresses with original instructions ================================ */

if (!file_exists("$outputDirectory/$inputBasename+22.lst")) {
  echo "[-] JWasm failed to produce .lst file.\n"
     . "    You will not be able to toggle between converted and original x64 instructions.\n"
     . "\n";
} else {
  echo "[.] Mapping listing addresses to original x64 instructions\n";

  $instrCount = 0;

  $origInstrIdc  = "static initOrigInstr() {\n"
                 . "  auto segEa, segName, origArr;\n"
                 . "  origArr = GetArrayId(\"plus22_original_instructions\");\n"
                 . "  if (origArr == -1) {\n"
                 . "    origArr = CreateArray(\"plus22_original_instructions\");\n"
                 . "  }\n"
                 . "\n";

  $lst = explode("\n", file_get_contents("$outputDirectory/$inputBasename+22.lst"));
  array_splice($lst, 0, 2);
  $origLines = count($origF);
  if ($origF[$origLines - 1] == "") {
    $origLines--;
  }

  $insideSegment = false;
  for ($i = 0; $i < $origLines; $i++) {
    $origLn = trim($origF[$i]);
    $meta = explode(" ", trim(substr($lst[$i], 0, 32)), 2);
    $offset = $meta[0];
    if (!preg_match('#^[0-9A-F]{8}$#s', $offset)) {
      continue;
    }
    $bytecode = isset($meta[1]) ? trim($meta[1]) : "";
    if ($insideSegment === false && $offset == "00000000") {
      if (preg_match('#^\s*(\w+)\s+segment\b#s', $origLn, $mt)) {
        $segName = $mt[1];
        $segNameDot = strtr($segName, '_', '.');
        $insideSegment = $segName;
        $origInstrIdc .= "  for (segEa = 0; segEa != BADADDR; segEa = NextSeg(segEa)) {\n"
                       . "    segName = SegName(segEa);\n"
                       . "    if (segName != 0) {\n"
                       . "      if (segName == \"$segName\" || segName == \"$segNameDot\") {\n"
                       . "        break;\n"
                       . "      }\n"
                       . "    }\n"
                       . "  }\n"
                       . "  if (segEa != BADADDR) {\n";
      }
    } else {
      if (!preg_match('#^\s*' . $insideSegment . '\s+ends\b#s', $origLn, $mt)) {
        if (!empty($bytecode)) {
          while (($pos = strpos($origLn, "\t")) !== false) {
            $origLn = substr_replace($origLn, str_repeat(" ", 8 - $pos % 8), $pos, 1);
          }
          $origLn = str_replace(array('\\', '"'), array('\\\\', '\\"'), $origLn);
          $origInstrIdc .= "    SetArrayString(origArr, segEa + 0x$offset, \"$origLn\");\n";
          $instrCount++;
        }
      } else {
        $origInstrIdc .= "  }\n\n";
        $insideSegment = false;
      }
    }
  }
  if ($insideSegment !== false) {
    $origInstrIdc .= "  }\n\n";
  }

  $origInstrIdc .= "  SetArrayLong(origArr, BADADDR, 0);\n"
                 . "}\n"
                 . "\n";

  file_put_contents("$outputDirectory/$inputBasename+22.idc", $origInstrIdc, FILE_APPEND);
  echo "[+] Extended IDC with $instrCount original instructions - press Alt-Z in IDA\n\n";

  if (! $verboseMode) {
    @unlink("$outputDirectory/$inputBasename+22.lst");
  }
}

/* === Apply types with IDA and IDC script ========================================== */

$pluses = "+++++";
$ext = "obj";

if ($idaFoundPath === false) {
  echo "[-] To set function types and original instructions automatically you need to specify where your IDA is.\n"
     . "    Modify \$idaPaths variable to include your IDA installation path.\n"
     . "    Or run IDC script by hand\n";
} else {
  echo "[*] Setting function types with IDA\n";
  @unlink("$outputDirectory/$idbBasename+22.idb");
  @unlink("$outputDirectory/$idbBasename+22.id0");
  @unlink("$outputDirectory/$idbBasename+22.id1");
  @unlink("$outputDirectory/$idbBasename+22.nam");
  @unlink("$outputDirectory/$idbBasename+22.til");
  system("$idaFoundPath\\idaq.exe -A \"-S$inputBasename+22.idc\" \"$outputDirectory/$inputBasename+22.obj\"");

  if (!file_exists("$outputDirectory/$inputBasename+22.idb")) {
    echo "[-] IDA failed to produce .idb file with types. You can try to restore types by running $inputBasename+22.idc\n";
    $pluses = "++";
  } else {
    echo "[+] Produced $inputBasename+22.idb with correct types\n";
    if (! $verboseMode) {
      @unlink("$outputDirectory/$inputBasename+22.idc");
    }
    $ext = "idb";

    if (file_exists("$idaFoundPath/idc/ida.idc") && !strstr(file_get_contents("$idaFoundPath/idc/ida.idc"), "Plus22_toggleOrigInstr")) {
      echo "\n[/!\\] Plus22 can now show you original x64 instructions right in IDA by pressing Alt-Z.\n"
         . "      However, for it to work, your startup IDC script must be patched.\n"
         . "[?] Do you want to have your 'idc/ida.idc' patched now? [y] ";
      if (strtolower(substr(fgets(STDIN), 0, 1)) != 'n') {
        copy("$idaFoundPath/idc/ida.idc", "$idaFoundPath/idc/ida.idc.bak");
        $idaIdc = file_get_contents("$idaFoundPath/idc/ida.idc");
        $idaIdc = preg_replace('#[^\n]\s*static\s+main\(.+\{#s', "$0\n  AddHotkey(\"Alt-Z\", \"Plus22_toggleOrigInstr\");\n  if (GetArrayId(\"plus22_original_instructions\") != -1) {\n    Message(\"+--------------------------------------------------------------------------------------------------------------+\\n| +22: original instruction data found. Press Alt-Z to toggle between converted and original x64 instructions. |\\n+--------------------------------------------------------------------------------------------------------------+\\n\");\n  }\n", $idaIdc);
        $idaIdc .= "\n"
                 . "static Plus22_toggleOrigInstr() {\n"
                 . "  auto ea, origArr;\n"
                 . "  origArr = GetArrayId(\"plus22_original_instructions\");\n"
                 . "  if (origArr == -1) {\n"
                 . "    Message(\"+22: original instruction data not found in this database.\\n\");\n"
                 . "    return;\n"
                 . "  }\n\n"
                 . "  if (GetArrayElement(AR_LONG, origArr, BADADDR)) {\n"
                 . "    for (ea = GetFirstIndex(AR_STR, origArr); ea != -1 && ea != BADADDR; ea = GetNextIndex(AR_STR, origArr, ea)) {\n"
                 . "      SetManualInsn(ea, \"\");\n"
                 . "    }\n"
                 . "    SetArrayLong(origArr, BADADDR, 0);\n"
                 . "  } else {\n"
                 . "    for (ea = GetFirstIndex(AR_STR, origArr); ea != -1 && ea != BADADDR; ea = GetNextIndex(AR_STR, origArr, ea)) {\n"
                 . "      SetManualInsn(ea, GetArrayElement(AR_STR, origArr, ea));\n"
                 . "    }\n"
                 . "    SetArrayLong(origArr, BADADDR, 1);\n"
                 . "  }\n"
                 . "}\n";
        file_put_contents("$idaFoundPath/idc/ida.idc", $idaIdc);
        echo "[+] 'idc/ida.idc' patched. Press Alt-Z to toggle between converted and original instructions.\n";
      }
    }
  }
}

echo "\n[$pluses] Success!\n"
   . "\n"
   . "[!] Now open $inputBasename+22.$ext in Hex-Rays, and GO GO PWN!\n";
exit(0);
