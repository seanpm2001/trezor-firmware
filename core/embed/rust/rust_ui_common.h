#include "common.h"

void screen_fatal_error_rust(const char* title, const char* msg,
                             const char* footer);

void screen_boot_stage_2(void);

void display_image(int16_t x, int16_t y, const uint8_t* data, uint32_t datalen);
void display_icon(int16_t x, int16_t y, const uint8_t* data, uint32_t datalen,
                  uint16_t fg_color, uint16_t bg_color);
