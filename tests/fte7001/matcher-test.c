/* matcher-test.c — fte7001-matcher 离线回归测试（零依赖，可直接编译运行）
 *
 * 夹具 tests/matcher-fixture.h 为纯合成纹理（正弦脊线+暗点+噪声，见该文件
 * 头注释），不含任何真实指纹数据。期望值由 tools/kp-matcher-prototype.py
 * 在相同字节上算出（Python 原型与 C 移植的"同图同分"契约）。
 *
 * 断言：
 *   1) 同图自比 = 100.0（确定性/随机流契约）
 *   2) 45 对"同指"全部 ≥ 7.0（不漏真指）
 *   3) 50 对"异指"全部 < 7.0（不误识）
 *   4) 重复打分逐位一致（RANSAC 随机流固定）
 *
 * 编译运行：
 *   cc -O2 -I tests -I driver tests/matcher-test.c driver/fte7001-matcher.c -lm \
 *     -o /tmp/matcher-test && /tmp/matcher-test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fte7001-matcher.h"
#include "matcher-fixture.h"

static int n_fail = 0;

static void
check (int cond, const char *what)
{
  printf ("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
  if (!cond)
    n_fail++;
}

static float
score_frames (const unsigned char *a, const unsigned char *b)
{
  Fte7001Frame fa, fb;
  Fte7001FeatureSet fsa, fsb;
  float s;

  memcpy (fa.pixels, a, FT9338_IMG_SIZE);
  memcpy (fb.pixels, b, FT9338_IMG_SIZE);
  fsa = fte7001_feature_extract (&fa);
  fsb = fte7001_feature_extract (&fb);
  s = fte7001_match_score (&fsa, &fsb);
  fte7001_feature_set_free (&fsa);
  fte7001_feature_set_free (&fsb);
  return s;
}

int
main (void)
{
  int i, j;
  int same_ok = 1, diff_ok = 1;
  float same_min = 1e9f, diff_max = -1e9f;

  printf ("== matcher 离线回归（合成夹具，阈值 %.1f）==\n",
          FT9338_MATCH_THRESHOLD);

  /* 1) 同图自比 */
  {
    float s = score_frames (FIXTURE_SAME[0], FIXTURE_SAME[0]);
    char what[128];
    snprintf (what, sizeof (what), "自比 s00×s00 = %.1f（期望 100.0）", s);
    check (s == 100.0f, what);
  }

  /* 4) 确定性：同一对打分两次逐位一致 */
  {
    float s1 = score_frames (FIXTURE_SAME[3], FIXTURE_SAME[7]);
    float s2 = score_frames (FIXTURE_SAME[3], FIXTURE_SAME[7]);
    char what[128];
    snprintf (what, sizeof (what), "重复打分一致（%.2f vs %.2f）", s1, s2);
    check (s1 == s2, what);
  }

  /* 2) 同指 45 对全部命中 */
  for (i = 0; i < FIXTURE_SAME_COUNT; i++)
    for (j = i + 1; j < FIXTURE_SAME_COUNT; j++)
      {
        float s = score_frames (FIXTURE_SAME[i], FIXTURE_SAME[j]);
        if (s < same_min)
          same_min = s;
        if (s < FT9338_MATCH_THRESHOLD)
          {
            printf ("    同指漏报: s%02d×s%02d = %.2f\n", i, j, s);
            same_ok = 0;
          }
      }
  {
    char what[128];
    snprintf (what, sizeof (what), "同指 45 对全部 ≥ 阈值（min %.1f）",
              same_min);
    check (same_ok, what);
  }

  /* 3) 异指 50 对全部拒绝 */
  for (i = 0; i < FIXTURE_SAME_COUNT; i++)
    for (j = 0; j < FIXTURE_DIFF_COUNT; j++)
      {
        float s = score_frames (FIXTURE_SAME[i], FIXTURE_DIFF[j]);
        if (s > diff_max)
          diff_max = s;
        if (s >= FT9338_MATCH_THRESHOLD)
          {
            printf ("    异指误识: s%02d×d%02d = %.2f\n", i, j, s);
            diff_ok = 0;
          }
      }
  {
    char what[128];
    snprintf (what, sizeof (what), "异指 50 对全部 < 阈值（max %.1f）",
              diff_max);
    check (diff_ok, what);
  }

  printf ("== %s ==\n", n_fail == 0 ? "全部通过" : "存在失败项");
  return n_fail == 0 ? 0 : 1;
}
