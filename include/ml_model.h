#pragma once
#include <cstdarg>
namespace Eloquent {
    namespace ML {
        namespace Port {
            class RandomForest {
                public:
                    /**
                    * Predict class for features vector
                    */
                    int predict(float *x) {
                        uint8_t votes[4] = { 0 };
                        // tree #1
                        if (x[7] <= 7.0) {
                            if (x[0] <= 384.0) {
                                if (x[9] <= 99.5) {
                                    if (x[2] <= 254.0) {
                                        votes[2] += 1;
                                    }

                                    else {
                                        votes[3] += 1;
                                    }
                                }

                                else {
                                    if (x[9] <= 100.5) {
                                        if (x[3] <= 119.0) {
                                            votes[2] += 1;
                                        }

                                        else {
                                            votes[3] += 1;
                                        }
                                    }

                                    else {
                                        if (x[9] <= 117.5) {
                                            if (x[9] <= 103.5) {
                                                votes[2] += 1;
                                            }

                                            else {
                                                if (x[9] <= 106.5) {
                                                    if (x[3] <= 119.0) {
                                                        votes[2] += 1;
                                                    }

                                                    else {
                                                        votes[3] += 1;
                                                    }
                                                }

                                                else {
                                                    if (x[3] <= 119.0) {
                                                        votes[2] += 1;
                                                    }

                                                    else {
                                                        votes[3] += 1;
                                                    }
                                                }
                                            }
                                        }

                                        else {
                                            if (x[3] <= 119.0) {
                                                votes[2] += 1;
                                            }

                                            else {
                                                votes[3] += 1;
                                            }
                                        }
                                    }
                                }
                            }

                            else {
                                votes[2] += 1;
                            }
                        }

                        else {
                            if (x[5] <= 238.0) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #2
                        if (x[3] <= 1.5) {
                            votes[2] += 1;
                        }

                        else {
                            if (x[3] <= 246.5) {
                                if (x[4] <= 3.0) {
                                    votes[3] += 1;
                                }

                                else {
                                    votes[1] += 1;
                                }
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #3
                        if (x[8] <= 1.0) {
                            if (x[3] <= 119.0) {
                                votes[2] += 1;
                            }

                            else {
                                votes[3] += 1;
                            }
                        }

                        else {
                            if (x[2] <= 253.5) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #4
                        if (x[5] <= 9.5) {
                            if (x[3] <= 119.0) {
                                votes[2] += 1;
                            }

                            else {
                                votes[3] += 1;
                            }
                        }

                        else {
                            if (x[2] <= 253.5) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #5
                        if (x[7] <= 7.0) {
                            if (x[2] <= 254.0) {
                                votes[2] += 1;
                            }

                            else {
                                votes[3] += 1;
                            }
                        }

                        else {
                            if (x[3] <= 247.5) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #6
                        if (x[5] <= 1.0) {
                            if (x[3] <= 119.0) {
                                votes[2] += 1;
                            }

                            else {
                                votes[3] += 1;
                            }
                        }

                        else {
                            if (x[7] <= 251.0) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #7
                        if (x[3] <= 1.5) {
                            votes[2] += 1;
                        }

                        else {
                            if (x[0] <= 24.5) {
                                votes[0] += 1;
                            }

                            else {
                                if (x[8] <= 1.0) {
                                    votes[3] += 1;
                                }

                                else {
                                    votes[1] += 1;
                                }
                            }
                        }

                        // tree #8
                        if (x[7] <= 10.5) {
                            if (x[2] <= 254.0) {
                                votes[2] += 1;
                            }

                            else {
                                votes[3] += 1;
                            }
                        }

                        else {
                            if (x[5] <= 248.5) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #9
                        if (x[2] <= 254.0) {
                            if (x[3] <= 1.5) {
                                votes[2] += 1;
                            }

                            else {
                                votes[1] += 1;
                            }
                        }

                        else {
                            if (x[8] <= 127.5) {
                                if (x[0] <= 384.0) {
                                    votes[3] += 1;
                                }

                                else {
                                    votes[2] += 1;
                                }
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #10
                        if (x[5] <= 1.0) {
                            if (x[9] <= 252.0) {
                                if (x[2] <= 254.0) {
                                    votes[2] += 1;
                                }

                                else {
                                    if (x[3] <= 119.0) {
                                        votes[2] += 1;
                                    }

                                    else {
                                        votes[3] += 1;
                                    }
                                }
                            }

                            else {
                                if (x[3] <= 119.0) {
                                    votes[2] += 1;
                                }

                                else {
                                    votes[3] += 1;
                                }
                            }
                        }

                        else {
                            if (x[7] <= 251.0) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #11
                        if (x[3] <= 1.5) {
                            votes[2] += 1;
                        }

                        else {
                            if (x[6] <= 251.0) {
                                if (x[7] <= 14.0) {
                                    votes[3] += 1;
                                }

                                else {
                                    votes[1] += 1;
                                }
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #12
                        if (x[7] <= 11.0) {
                            if (x[3] <= 119.0) {
                                votes[2] += 1;
                            }

                            else {
                                votes[3] += 1;
                            }
                        }

                        else {
                            if (x[9] <= 253.5) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #13
                        if (x[2] <= 254.0) {
                            if (x[7] <= 7.0) {
                                votes[2] += 1;
                            }

                            else {
                                votes[1] += 1;
                            }
                        }

                        else {
                            if (x[8] <= 127.5) {
                                if (x[3] <= 119.0) {
                                    votes[2] += 1;
                                }

                                else {
                                    votes[3] += 1;
                                }
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #14
                        if (x[6] <= 10.0) {
                            if (x[9] <= 251.5) {
                                if (x[0] <= 384.0) {
                                    if (x[3] <= 119.0) {
                                        votes[2] += 1;
                                    }

                                    else {
                                        votes[3] += 1;
                                    }
                                }

                                else {
                                    votes[2] += 1;
                                }
                            }

                            else {
                                if (x[9] <= 253.5) {
                                    if (x[9] <= 252.5) {
                                        if (x[2] <= 251.5) {
                                            votes[2] += 1;
                                        }

                                        else {
                                            votes[3] += 1;
                                        }
                                    }

                                    else {
                                        if (x[2] <= 244.5) {
                                            votes[2] += 1;
                                        }

                                        else {
                                            votes[3] += 1;
                                        }
                                    }
                                }

                                else {
                                    if (x[0] <= 384.0) {
                                        if (x[9] <= 254.5) {
                                            if (x[3] <= 119.0) {
                                                votes[2] += 1;
                                            }

                                            else {
                                                votes[3] += 1;
                                            }
                                        }

                                        else {
                                            votes[2] += 1;
                                        }
                                    }

                                    else {
                                        votes[2] += 1;
                                    }
                                }
                            }
                        }

                        else {
                            if (x[7] <= 242.0) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #15
                        if (x[3] <= 1.5) {
                            votes[2] += 1;
                        }

                        else {
                            if (x[5] <= 248.5) {
                                if (x[4] <= 4.0) {
                                    votes[3] += 1;
                                }

                                else {
                                    votes[1] += 1;
                                }
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #16
                        if (x[2] <= 254.0) {
                            if (x[6] <= 10.0) {
                                votes[2] += 1;
                            }

                            else {
                                votes[1] += 1;
                            }
                        }

                        else {
                            if (x[0] <= 128.0) {
                                votes[0] += 1;
                            }

                            else {
                                if (x[3] <= 119.0) {
                                    votes[2] += 1;
                                }

                                else {
                                    votes[3] += 1;
                                }
                            }
                        }

                        // tree #17
                        if (x[3] <= 1.5) {
                            votes[2] += 1;
                        }

                        else {
                            if (x[0] <= 24.5) {
                                votes[0] += 1;
                            }

                            else {
                                if (x[4] <= 4.0) {
                                    votes[3] += 1;
                                }

                                else {
                                    votes[1] += 1;
                                }
                            }
                        }

                        // tree #18
                        if (x[4] <= 3.0) {
                            if (x[9] <= 251.5) {
                                if (x[9] <= 117.5) {
                                    if (x[2] <= 254.0) {
                                        votes[2] += 1;
                                    }

                                    else {
                                        votes[3] += 1;
                                    }
                                }

                                else {
                                    if (x[2] <= 254.0) {
                                        votes[2] += 1;
                                    }

                                    else {
                                        votes[3] += 1;
                                    }
                                }
                            }

                            else {
                                if (x[3] <= 119.0) {
                                    votes[2] += 1;
                                }

                                else {
                                    votes[3] += 1;
                                }
                            }
                        }

                        else {
                            if (x[5] <= 248.5) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #19
                        if (x[4] <= 4.0) {
                            if (x[0] <= 384.0) {
                                if (x[9] <= 251.5) {
                                    if (x[9] <= 220.5) {
                                        if (x[2] <= 254.0) {
                                            votes[2] += 1;
                                        }

                                        else {
                                            votes[3] += 1;
                                        }
                                    }

                                    else {
                                        votes[2] += 1;
                                    }
                                }

                                else {
                                    if (x[3] <= 119.0) {
                                        votes[2] += 1;
                                    }

                                    else {
                                        votes[3] += 1;
                                    }
                                }
                            }

                            else {
                                votes[2] += 1;
                            }
                        }

                        else {
                            if (x[9] <= 253.5) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // tree #20
                        if (x[4] <= 4.0) {
                            if (x[9] <= 252.5) {
                                if (x[9] <= 105.5) {
                                    if (x[2] <= 254.0) {
                                        votes[2] += 1;
                                    }

                                    else {
                                        votes[3] += 1;
                                    }
                                }

                                else {
                                    if (x[3] <= 119.0) {
                                        votes[2] += 1;
                                    }

                                    else {
                                        votes[3] += 1;
                                    }
                                }
                            }

                            else {
                                if (x[0] <= 384.0) {
                                    if (x[3] <= 119.0) {
                                        votes[2] += 1;
                                    }

                                    else {
                                        votes[3] += 1;
                                    }
                                }

                                else {
                                    votes[2] += 1;
                                }
                            }
                        }

                        else {
                            if (x[8] <= 254.5) {
                                votes[1] += 1;
                            }

                            else {
                                votes[0] += 1;
                            }
                        }

                        // return argmax of votes
                        uint8_t classIdx = 0;
                        float maxVotes = votes[0];

                        for (uint8_t i = 1; i < 4; i++) {
                            if (votes[i] > maxVotes) {
                                classIdx = i;
                                maxVotes = votes[i];
                            }
                        }

                        return classIdx;
                    }

                protected:
                };
            }
        }
    }