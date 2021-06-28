/* Copyright 2021 Mozilla Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Widths of glyphes in LiberationSans-Regular.ttf.
const LiberationSansRegularWidths = [
  365, 0, 667, 1000, 1000, 667, 667, 667, 667, 667, 667, 667, 667, 667, 667,
  667, 667, 667, 667, 722, 722, 722, 722, 722, 722, 667, 722, 722, 722, 668,
  667, 667, 667, 667, 667, 667, 667, 667, 667, 723, 667, 667, 784, 722, 838,
  722, 556, 611, 778, 551, 778, 778, 778, 778, 722, 604, 354, 354, 604, 722,
  722, 278, 735, 278, 278, 278, 278, 278, 278, 278, 278, 278, 278, 384, 278,
  500, 500, 667, 667, 667, 556, 556, 668, 556, 556, 556, 556, 833, 833, 722,
  722, 722, 722, 722, 722, 778, 1000, 778, 778, 778, 778, 778, 778, 778, 748,
  752, 778, 774, 778, 778, 778, 667, 798, 722, 835, 778, 722, 722, 722, 722,
  667, 667, 708, 708, 708, 708, 708, 708, 708, 708, 708, 708, 625, 708, 708,
  708, 708, 708, 708, 708, 708, 708, 708, 708, 708, 708, 708, 708, 708, 708,
  708, 708, 708, 708, 708, 708, 708, 708, 708, 708, 708, 708, 667, 667, 667,
  667, 667, 618, 611, 611, 611, 611, 611, 778, 667, 722, 722, 722, 722, 722,
  722, 722, 722, 722, 667, 667, 855, 722, 722, 667, 944, 944, 944, 944, 944,
  667, 650, 667, 667, 667, 667, 667, 611, 611, 611, 611, 611, 556, 556, 556,
  556, 333, 556, 889, 889, 1000, 667, 656, 667, 542, 677, 667, 667, 923, 604,
  719, 719, 583, 656, 833, 722, 778, 719, 667, 722, 611, 635, 760, 667, 740,
  667, 917, 938, 792, 885, 656, 719, 1010, 722, 489, 865, 542, 719, 667, 278,
  278, 500, 1057, 1010, 854, 583, 635, 556, 573, 531, 365, 583, 556, 556, 669,
  458, 559, 559, 438, 583, 688, 552, 556, 542, 556, 500, 458, 500, 823, 500,
  573, 521, 802, 823, 625, 719, 521, 510, 750, 542, 411, 556, 365, 510, 500,
  222, 278, 222, 906, 812, 556, 438, 500, 719, 778, 552, 556, 885, 323, 1073,
  556, 578, 578, 556, 667, 278, 556, 549, 556, 556, 1000, 500, 1000, 1000, 500,
  500, 500, 469, 584, 389, 1015, 556, 556, 278, 260, 575, 708, 334, 334, 278,
  278, 333, 260, 350, 500, 500, 333, 500, 500, 500, 500, 333, 556, 525, 604,
  333, 656, 278, 278, 737, 556, 556, 556, 556, 615, 556, 400, 557, 510, 333,
  333, 549, 729, 708, 556, 333, 278, 556, 556, 556, 556, 556, 556, 556, 556,
  556, 1000, 556, 1000, 556, 556, 556, 446, 446, 584, 583, 600, 556, 556, 556,
  278, 500, 333, 278, 750, 604, 1000, 556, 834, 556, 556, 556, 556, 500, 556,
  556, 556, 556, 611, 333, 222, 222, 294, 294, 324, 324, 316, 328, 398, 285,
  333, 584, 549, 556, 556, 333, 333, 556, 556, 556, 594, 604, 333, 222, 278,
  278, 278, 278, 278, 444, 278, 713, 274, 604, 604, 719, 604, 604, 1052, 222,
  222, 222, 222, 222, 278, 222, 222, 500, 500, 500, 500, 222, 222, 500, 292,
  222, 334, 584, 549, 708, 556, 584, 222, 494, 222, 708, 833, 552, 750, 333,
  584, 188, 576, 584, 500, 750, 556, 556, 604, 556, 556, 556, 333, 549, 556,
  500, 556, 556, 556, 556, 556, 556, 944, 333, 556, 556, 556, 781, 781, 556,
  556, 556, 834, 834, 834, 354, 370, 365, 979, 611, 611, 556, 556, 537, 333,
  333, 494, 889, 278, 1000, 1094, 648, 690, 584, 549, 823, 713, 556, 556, 611,
  355, 333, 333, 333, 222, 222, 222, 222, 191, 333, 333, 549, 333, 333, 737,
  584, 569, 333, 708, 500, 500, 500, 500, 500, 500, 354, 556, 556, 834, 708,
  617, 482, 556, 278, 1021, 531, 556, 713, 917, 278, 395, 278, 375, 278, 556,
  556, 556, 834, 834, 333, 333, 1000, 990, 990, 990, 990, 556, 556, 556, 556,
  556, 556, 556, 556, 556, 556, 552, 278, 333, 333, 333, 576, 333, 611, 278,
  333, 278, 667, 722, 556, 559, 333, 333, 333, 333, 333, 333, 333, 365, 768,
  612, 167, 278, 750, 333, 333, 500, 500, 556, 708, 547, 547, 547, 547, 556,
  556, 500, 722, 722, 722, 722, 722, 500, 448, 500, 500, 500, 500, 556, 500,
  500, 500, 500, 500, 556, 441,
];

export { LiberationSansRegularWidths };
