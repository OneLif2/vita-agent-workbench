#ifndef INA_VITA_DIALOG_OPTIONS
#define INA_VITA_DIALOG_OPTIONS
#include <psp2/system_param.h>

static inline SceSystemParamLang choose_dialog_language(int rc,int value) {
    return (rc==0 && value>=(int)SCE_SYSTEM_PARAM_LANG_JAPANESE && value<=(int)SCE_SYSTEM_PARAM_LANG_TURKISH)
        ? (SceSystemParamLang)value : SCE_SYSTEM_PARAM_LANG_ENGLISH_US;
}

static inline SceSystemParamEnterButtonAssign choose_dialog_confirm(int rc,int value) {
    return (rc==0 && (value==SCE_SYSTEM_PARAM_ENTER_BUTTON_CIRCLE || value==SCE_SYSTEM_PARAM_ENTER_BUTTON_CROSS))
        ? (SceSystemParamEnterButtonAssign)value : SCE_SYSTEM_PARAM_ENTER_BUTTON_CROSS;
}
#endif
