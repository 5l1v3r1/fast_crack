/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_rp_optimized.h"
#include "inc_rp_optimized.cl"
#include "inc_simd.cl"
#include "inc_hash_md5.cl"
#include "inc_hash_sha1.cl"
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

KERNEL_FQ void m21200_m04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc table
   */

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[ 3];
  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[ 4];
  salt_buf1[1] = 0;
  salt_buf1[2] = 0;
  salt_buf1[3] = 0;

  const u32 salt_len  = salt_bufs[salt_pos].salt_len;

  append_0x80_2x4_S (salt_buf0, salt_buf1, salt_len);

  /**
   * sha1(salt)
   */

  u32x w0_t = hc_swap32 (salt_buf0[0]);
  u32x w1_t = hc_swap32 (salt_buf0[1]);
  u32x w2_t = hc_swap32 (salt_buf0[2]);
  u32x w3_t = hc_swap32 (salt_buf0[3]);
  u32x w4_t = hc_swap32 (salt_buf1[0]);
  u32x w5_t = 0;
  u32x w6_t = 0;
  u32x w7_t = 0;
  u32x w8_t = 0;
  u32x w9_t = 0;
  u32x wa_t = 0;
  u32x wb_t = 0;
  u32x wc_t = 0;
  u32x wd_t = 0;
  u32x we_t = 0;
  u32x wf_t = salt_len * 8;

  u32x a = SHA1M_A;
  u32x b = SHA1M_B;
  u32x c = SHA1M_C;
  u32x d = SHA1M_D;
  u32x e = SHA1M_E;

  #undef K
  #define K SHA1C00

  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, we_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w7_t);
  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wb_t);
  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t);
  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb_t);
  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t);
  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7_t);
  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t);
  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w7_t);
  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wb_t);
  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wf_t);

  a += SHA1M_A;
  b += SHA1M_B;
  c += SHA1M_C;
  d += SHA1M_D;
  e += SHA1M_E;

  const u32x a0 = a;
  const u32x b0 = b;
  const u32x c0 = c;
  const u32x d0 = d;
  const u32x e0 = e;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * md5
     */

    w0_t = w0[0];
    w1_t = w0[1];
    w2_t = w0[2];
    w3_t = w0[3];
    w4_t = w1[0];
    w5_t = w1[1];
    w6_t = w1[2];
    w7_t = w1[3];
    w8_t = w2[0];
    w9_t = w2[1];
    wa_t = w2[2];
    wb_t = w2[3];
    wc_t = w3[0];
    wd_t = w3[1];
    we_t = out_len * 8;
    wf_t = 0;

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w5_t, MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w8_t, MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wb_t, MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, we_t, MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w1_t, MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w4_t, MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w7_t, MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, wa_t, MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, wd_t, MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t, MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t, MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w6_t, MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w9_t, MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, wc_t, MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wf_t, MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t, MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

    a += MD5M_A;
    b += MD5M_B;
    c += MD5M_C;
    d += MD5M_D;

    const u32x a1 = hc_swap32 (a);
    const u32x b1 = hc_swap32 (b);
    const u32x c1 = hc_swap32 (c);
    const u32x d1 = hc_swap32 (d);

    /**
     * md5
     */

    w0_t = uint_to_hex_lower8 ((a0 >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((a0 >> 16) & 255) << 16;
    w1_t = uint_to_hex_lower8 ((a0 >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((a0 >>  0) & 255) << 16;
    w2_t = uint_to_hex_lower8 ((b0 >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((b0 >> 16) & 255) << 16;
    w3_t = uint_to_hex_lower8 ((b0 >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((b0 >>  0) & 255) << 16;
    w4_t = uint_to_hex_lower8 ((c0 >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((c0 >> 16) & 255) << 16;
    w5_t = uint_to_hex_lower8 ((c0 >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((c0 >>  0) & 255) << 16;
    w6_t = uint_to_hex_lower8 ((d0 >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((d0 >> 16) & 255) << 16;
    w7_t = uint_to_hex_lower8 ((d0 >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((d0 >>  0) & 255) << 16;
    w8_t = uint_to_hex_lower8 ((e0 >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((e0 >> 16) & 255) << 16;
    w9_t = uint_to_hex_lower8 ((e0 >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((e0 >>  0) & 255) << 16;
    wa_t = 0;
    wb_t = 0;
    wc_t = 0;
    wd_t = 0;
    we_t = 0;
    wf_t = 0;

    // ctx len 40, pos 40

    w0[0] = uint_to_hex_lower8 ((a1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((a1 >> 16) & 255) << 16;
    w0[1] = uint_to_hex_lower8 ((a1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((a1 >>  0) & 255) << 16;
    w0[2] = uint_to_hex_lower8 ((b1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((b1 >> 16) & 255) << 16;
    w0[3] = uint_to_hex_lower8 ((b1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((b1 >>  0) & 255) << 16;
    w1[0] = uint_to_hex_lower8 ((c1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((c1 >> 16) & 255) << 16;
    w1[1] = uint_to_hex_lower8 ((c1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((c1 >>  0) & 255) << 16;
    w1[2] = uint_to_hex_lower8 ((d1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((d1 >> 16) & 255) << 16;
    w1[3] = uint_to_hex_lower8 ((d1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((d1 >>  0) & 255) << 16;

    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    u32x _w0[4] = { 0 };
    u32x _w1[4] = { 0 };
    u32x _w2[4] = { 0 };
    u32x _w3[4] = { 0 };

    switch_buffer_by_offset_carry_le (w0, w1, w2, w3, _w0, _w1, _w2, _w3, 40);

    w0_t |= w0[0];
    w1_t |= w0[1];
    w2_t |= w0[2];
    w3_t |= w0[3];
    w4_t |= w1[0];
    w5_t |= w1[1];
    w6_t |= w1[2];
    w7_t |= w1[3];
    w8_t |= w2[0];
    w9_t |= w2[1];
    wa_t |= w2[2];
    wb_t |= w2[3];
    wc_t |= w3[0];
    wd_t |= w3[1];
    we_t |= w3[2];
    wf_t |= w3[3];

    // md5 transform

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    u32x digest[4];

    digest[0] = a;
    digest[1] = b;
    digest[2] = c;
    digest[3] = d;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

    MD5_STEP (MD5_H1, a, b, c, d, w5_t, MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w8_t, MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wb_t, MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, we_t, MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w1_t, MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w4_t, MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w7_t, MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, wa_t, MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, wd_t, MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t, MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t, MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w6_t, MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w9_t, MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, wc_t, MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wf_t, MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t, MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;

    w0[0] = _w0[0];
    w0[1] = _w0[1];
    w0[2] = _w0[2];
    w0[3] = _w0[3];
    w1[0] = _w1[0];
    w1[1] = _w1[1];
    w1[2] = _w1[2];
    w1[3] = _w1[3];
    w2[0] = _w2[0];
    w2[1] = _w2[1];
    w2[2] = _w2[2];
    w2[3] = _w2[3];
    w3[0] = _w3[0];
    w3[1] = _w3[1];
    w3[2] = _w3[2];
    w3[3] = _w3[3];

    // ctx len 72, pos 8

    append_0x80_4x4 (w0, w1, w2, w3, 8);

    w3[2] = 72 * 8;
    w3[3] = 0;

    // md5 final transform

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];

    w0_t = w0[0];
    w1_t = w0[1];
    w2_t = w0[2];
    w3_t = w0[3];
    w4_t = w1[0];
    w5_t = w1[1];
    w6_t = w1[2];
    w7_t = w1[3];
    w8_t = w2[0];
    w9_t = w2[1];
    wa_t = w2[2];
    wb_t = w2[3];
    wc_t = w3[0];
    wd_t = w3[1];
    we_t = w3[2];
    wf_t = w3[3];

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

    MD5_STEP (MD5_H1, a, b, c, d, w5_t, MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w8_t, MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wb_t, MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, we_t, MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w1_t, MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w4_t, MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w7_t, MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, wa_t, MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, wd_t, MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t, MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t, MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w6_t, MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w9_t, MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, wc_t, MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wf_t, MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t, MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

    a += digest[0] - MD5M_A;
    b += digest[1] - MD5M_B;
    c += digest[2] - MD5M_C;
    d += digest[3] - MD5M_D;

    COMPARE_M_SIMD (a, d, c, b);
  }
}

KERNEL_FQ void m21200_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m21200_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m21200_s04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc table
   */

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[ 3];
  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[ 4];
  salt_buf1[1] = 0;
  salt_buf1[2] = 0;
  salt_buf1[3] = 0;

  const u32 salt_len  = salt_bufs[salt_pos].salt_len;

  append_0x80_2x4_S (salt_buf0, salt_buf1, salt_len);

  /**
   * sha1(salt)
   */

  u32x w0_t = hc_swap32 (salt_buf0[0]);
  u32x w1_t = hc_swap32 (salt_buf0[1]);
  u32x w2_t = hc_swap32 (salt_buf0[2]);
  u32x w3_t = hc_swap32 (salt_buf0[3]);
  u32x w4_t = hc_swap32 (salt_buf1[0]);
  u32x w5_t = 0;
  u32x w6_t = 0;
  u32x w7_t = 0;
  u32x w8_t = 0;
  u32x w9_t = 0;
  u32x wa_t = 0;
  u32x wb_t = 0;
  u32x wc_t = 0;
  u32x wd_t = 0;
  u32x we_t = 0;
  u32x wf_t = salt_len * 8;

  u32x a = SHA1M_A;
  u32x b = SHA1M_B;
  u32x c = SHA1M_C;
  u32x d = SHA1M_D;
  u32x e = SHA1M_E;

  #undef K
  #define K SHA1C00

  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, we_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w7_t);
  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wb_t);
  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t);
  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb_t);
  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t);
  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7_t);
  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t);
  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w7_t);
  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wb_t);
  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wf_t);

  a += SHA1M_A;
  b += SHA1M_B;
  c += SHA1M_C;
  d += SHA1M_D;
  e += SHA1M_E;

  const u32x a0 = a;
  const u32x b0 = b;
  const u32x c0 = c;
  const u32x d0 = d;
  const u32x e0 = e;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * md5
     */

    w0_t = w0[0];
    w1_t = w0[1];
    w2_t = w0[2];
    w3_t = w0[3];
    w4_t = w1[0];
    w5_t = w1[1];
    w6_t = w1[2];
    w7_t = w1[3];
    w8_t = w2[0];
    w9_t = w2[1];
    wa_t = w2[2];
    wb_t = w2[3];
    wc_t = w3[0];
    wd_t = w3[1];
    we_t = out_len * 8;
    wf_t = 0;

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w5_t, MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w8_t, MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wb_t, MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, we_t, MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w1_t, MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w4_t, MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w7_t, MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, wa_t, MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, wd_t, MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t, MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t, MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w6_t, MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w9_t, MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, wc_t, MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wf_t, MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t, MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

    a += MD5M_A;
    b += MD5M_B;
    c += MD5M_C;
    d += MD5M_D;

    const u32x a1 = hc_swap32 (a);
    const u32x b1 = hc_swap32 (b);
    const u32x c1 = hc_swap32 (c);
    const u32x d1 = hc_swap32 (d);

    /**
     * md5
     */

    w0_t = uint_to_hex_lower8 ((a0 >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((a0 >> 16) & 255) << 16;
    w1_t = uint_to_hex_lower8 ((a0 >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((a0 >>  0) & 255) << 16;
    w2_t = uint_to_hex_lower8 ((b0 >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((b0 >> 16) & 255) << 16;
    w3_t = uint_to_hex_lower8 ((b0 >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((b0 >>  0) & 255) << 16;
    w4_t = uint_to_hex_lower8 ((c0 >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((c0 >> 16) & 255) << 16;
    w5_t = uint_to_hex_lower8 ((c0 >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((c0 >>  0) & 255) << 16;
    w6_t = uint_to_hex_lower8 ((d0 >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((d0 >> 16) & 255) << 16;
    w7_t = uint_to_hex_lower8 ((d0 >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((d0 >>  0) & 255) << 16;
    w8_t = uint_to_hex_lower8 ((e0 >> 24) & 255) <<  0
         | uint_to_hex_lower8 ((e0 >> 16) & 255) << 16;
    w9_t = uint_to_hex_lower8 ((e0 >>  8) & 255) <<  0
         | uint_to_hex_lower8 ((e0 >>  0) & 255) << 16;
    wa_t = 0;
    wb_t = 0;
    wc_t = 0;
    wd_t = 0;
    we_t = 0;
    wf_t = 0;

    // ctx len 40, pos 40

    w0[0] = uint_to_hex_lower8 ((a1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((a1 >> 16) & 255) << 16;
    w0[1] = uint_to_hex_lower8 ((a1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((a1 >>  0) & 255) << 16;
    w0[2] = uint_to_hex_lower8 ((b1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((b1 >> 16) & 255) << 16;
    w0[3] = uint_to_hex_lower8 ((b1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((b1 >>  0) & 255) << 16;
    w1[0] = uint_to_hex_lower8 ((c1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((c1 >> 16) & 255) << 16;
    w1[1] = uint_to_hex_lower8 ((c1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((c1 >>  0) & 255) << 16;
    w1[2] = uint_to_hex_lower8 ((d1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((d1 >> 16) & 255) << 16;
    w1[3] = uint_to_hex_lower8 ((d1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((d1 >>  0) & 255) << 16;

    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    u32x _w0[4] = { 0 };
    u32x _w1[4] = { 0 };
    u32x _w2[4] = { 0 };
    u32x _w3[4] = { 0 };

    switch_buffer_by_offset_carry_le (w0, w1, w2, w3, _w0, _w1, _w2, _w3, 40);

    w0_t |= w0[0];
    w1_t |= w0[1];
    w2_t |= w0[2];
    w3_t |= w0[3];
    w4_t |= w1[0];
    w5_t |= w1[1];
    w6_t |= w1[2];
    w7_t |= w1[3];
    w8_t |= w2[0];
    w9_t |= w2[1];
    wa_t |= w2[2];
    wb_t |= w2[3];
    wc_t |= w3[0];
    wd_t |= w3[1];
    we_t |= w3[2];
    wf_t |= w3[3];

    // md5 transform

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    u32x digest[4];

    digest[0] = a;
    digest[1] = b;
    digest[2] = c;
    digest[3] = d;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

    MD5_STEP (MD5_H1, a, b, c, d, w5_t, MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w8_t, MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wb_t, MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, we_t, MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w1_t, MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w4_t, MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w7_t, MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, wa_t, MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, wd_t, MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t, MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t, MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w6_t, MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w9_t, MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, wc_t, MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wf_t, MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t, MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;

    w0[0] = _w0[0];
    w0[1] = _w0[1];
    w0[2] = _w0[2];
    w0[3] = _w0[3];
    w1[0] = _w1[0];
    w1[1] = _w1[1];
    w1[2] = _w1[2];
    w1[3] = _w1[3];
    w2[0] = _w2[0];
    w2[1] = _w2[1];
    w2[2] = _w2[2];
    w2[3] = _w2[3];
    w3[0] = _w3[0];
    w3[1] = _w3[1];
    w3[2] = _w3[2];
    w3[3] = _w3[3];

    // ctx len 72, pos 8

    append_0x80_4x4 (w0, w1, w2, w3, 8);

    w3[2] = 72 * 8;
    w3[3] = 0;

    // md5 final transform

    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];

    w0_t = w0[0];
    w1_t = w0[1];
    w2_t = w0[2];
    w3_t = w0[3];
    w4_t = w1[0];
    w5_t = w1[1];
    w6_t = w1[2];
    w7_t = w1[3];
    w8_t = w2[0];
    w9_t = w2[1];
    wa_t = w2[2];
    wb_t = w2[3];
    wc_t = w3[0];
    wd_t = w3[1];
    we_t = w3[2];
    wf_t = w3[3];

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

    MD5_STEP (MD5_H1, a, b, c, d, w5_t, MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w8_t, MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wb_t, MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, we_t, MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w1_t, MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w4_t, MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w7_t, MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, wa_t, MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, wd_t, MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t, MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t, MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w6_t, MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w9_t, MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, wc_t, MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, wf_t, MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t, MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);

    if (MATCHES_NONE_VS ((a+digest[0]-MD5M_A), search[0])) continue;

    MD5_STEP (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

    a += digest[0] - MD5M_A;
    b += digest[1] - MD5M_B;
    c += digest[2] - MD5M_C;
    d += digest[3] - MD5M_D;

    COMPARE_S_SIMD (a, d, c, b);
  }
}

KERNEL_FQ void m21200_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m21200_s16 (KERN_ATTR_RULES ())
{
}
