#include <idc.idc>

static main() {
  SetShortPrm(INF_AF2, GetShortPrm(INF_AF2) & ~AF2_HFLIRT & ~AF2_STKARG & ~AF2_REGARG);

  Wait();
  
  auto ea;
  for (ea = 0; ea != BADADDR; ea = NextFunction(ea)) {
    SetFunctionFlags(ea, GetFunctionFlags(ea) & ~FUNC_HIDDEN);
  }

  auto file = GetIdbPath()[0:-4] + ".asm";
  GenerateFile(OFILE_ASM, fopen(file, "w"), 0, BADADDR, GENFLG_ASMTYPE);
  Exit(0);
}
