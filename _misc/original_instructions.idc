#include <idc.idc>

static main(void)
{
  AddHotkey("Alt-Z", "Plus22_toggleOrigInstr");
  if (GetArrayId("plus22_original_instructions") != -1) {
    Message("+--------------------------------------------------------------------------------------------------------------+\n| +22: original instruction data found. Press Alt-Z to toggle between converted and original x64 instructions. |\n+--------------------------------------------------------------------------------------------------------------+\n");
  }
}

static Plus22_toggleOrigInstr() {
  auto ea, origArr;
  origArr = GetArrayId("plus22_original_instructions");
  if (origArr == -1) {
    Message("+22: original instruction data not found in this database.\n");
    return;
  }

  if (GetArrayElement(AR_LONG, origArr, BADADDR)) {
    for (ea = GetFirstIndex(AR_STR, origArr); ea != -1 && ea != BADADDR; ea = GetNextIndex(AR_STR, origArr, ea)) {
      SetManualInsn(ea, "");
    }
    SetArrayLong(origArr, BADADDR, 0);
  } else {
    for (ea = GetFirstIndex(AR_STR, origArr); ea != -1 && ea != BADADDR; ea = GetNextIndex(AR_STR, origArr, ea)) {
      SetManualInsn(ea, GetArrayElement(AR_STR, origArr, ea));
    }
    SetArrayLong(origArr, BADADDR, 1);
  }
} 