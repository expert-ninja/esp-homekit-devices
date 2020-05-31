/*
 * Espy House
 *
 * Copyright 2020 Expert Ninja
 *
 */

/*
 * Based on Home Accessory Architect (HAA) by José Antonio Jiménez Campos (@RavenSystem), licensed under Apache License 2.0.
 * https://github.com/RavenSystem/esp-homekit-devices
 *
 */
 
#ifndef __HAA_IR_CODE_H__
#define __HAA_IR_CODE_H__

//#define IR_CODE_DIGITS          2
#define IR_CODE_LEN             83
#define IR_CODE_LEN_2           (IR_CODE_LEN * IR_CODE_LEN)
#define IR_CODE_SCALE           5

const char baseRaw_dic[] = "0ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789+/!@#$%&()=?*,.;:-_<>";
const char baseUC_dic[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char baseLC_dic[] = "abcdefghijklmnopqrstuvwxyz";

#endif  // __HAA_IR_CODE_H__
