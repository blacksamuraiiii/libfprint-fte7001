/* fte7001-matcher.h — FTE7001 形态 B 关键点匹配器（FpDevice 形态）
 *
 * 参数全部照抄 tools/kp-matcher-prototype.py v3（2026-10-07 实测定稿）：
 * 留一验证 9 帧模板真指 10/10、异指 0/4、阈值 7.0。勿调参。
 *
 * 本单元纯 C99 + libm，无 GLib 依赖，可脱离 libfprint 单独编译测试。
 */
#ifndef FTE7001_MATCHER_H
#define FTE7001_MATCHER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- 图像与匹配参数（原型定稿，勿改） ---- */
#define FT9338_IMG_DIM 88                       /* 88×88 */
#define FT9338_IMG_SIZE (FT9338_IMG_DIM * FT9338_IMG_DIM)   /* 7744 */
#define FT9338_M_PATCH 16                       /* patch 16×16（2× 脊距 8px） */
#define FT9338_M_SIGMA_COUNT 4                  /* 高斯层数 */
#define FT9338_M_DESC_DIM 128                   /* 4×4 cells × 8 bins */
#define FT9338_M_LOWE_RATIO 0.9                 /* v3 放宽（0.8 杀真匹配） */
#define FT9338_M_RANSAC_ITERS 200               /* 相似变换迭代 */
#define FT9338_M_RANSAC_TOL 2.5                 /* 内点容差 px */
#define FT9338_M_MIN_FEATS 6                    /* 低于此特征数直接 0 分 */
#define FT9338_MATCH_THRESHOLD 7.0              /* 分界 4.2 倍的实测定稿 */
/* 质量闸门（附篇三 C.4 必配件）：d02 废片实测 cov=0.46/mtc=10.0 被正确拒绝 */
#define FT9338_Q_MIN_COVERAGE 0.70              /* 3×3 对比度>4 像素占比 */
#define FT9338_Q_MIN_MEAN_TC 15.0                /* 平均局部对比度 */

/* ---- 数据类型 ---- */

/* 一帧已取反的交付格式原图（88×88，1 B/px，调用方管理生命周期） */
typedef struct {
  uint8_t pixels[FT9338_IMG_SIZE];
} Fte7001Frame;

/* 关键点（原型 detect_keypoints 输出：(x, y, dog 值, 层号)） */
typedef struct {
  int x, y;
  float v;
  int layer;
} Fte7001Keypoint;

/* 描述子容器（描述子在 verify worker 逐帧现算，不缓存不序列化） */
typedef struct {
  Fte7001Keypoint *kps;        /* n_feats 个 */
  float (*descs)[FT9338_M_DESC_DIM];
  int n_feats;
} Fte7001FeatureSet;

/* ---- API ---- */

/* 质量闸门：coverage/mean_tc 出参可 NULL。返回 true=可入匹配器 */
bool fte7001_quality_check (const Fte7001Frame *frame,
                            float *coverage, float *mean_tc);

/* 特征提取（DoG 金字塔 σ=(2.0,2.8,4.0,5.7) + 16×16 主方向对齐描述子）。
 * 失败（特征数为 0 或内存不足）返回 n_feats==0 的空集，由调用方按
 * FT9338_M_MIN_FEATS 判 0 分。 */
Fte7001FeatureSet fte7001_feature_extract (const Fte7001Frame *frame);

/* 释放（对返回的 FeatureSet 必须 free，或传给本函数） */
void fte7001_feature_set_free (Fte7001FeatureSet *fs);

/* 归一化打分：probe 对单帧模板的相似 RANSAC 内点 / min(nA,nB) × 100。
 * 任何一侧特征数 < 6 直接 0.0。内部随机流固定（MT19937 seed 42，
 * 复现 Python random.Random(42)），同图同分。 */
float fte7001_match_score (const Fte7001FeatureSet *a,
                           const Fte7001FeatureSet *b);

#endif /* FTE7001_MATCHER_H */
