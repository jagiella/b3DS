#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 24 22:22:11 2022

@author: nick
"""
import numpy as np
import cv2


def rgb565to888(im):
    MASK5 = 0b011111
    MASK6 = 0b111111
    b = (im & MASK5) << 3
    g = ((im >> 5) & MASK6) << 2
    r = ((im >> (5 + 6)) & MASK5) << 3

    # Compose into one 3-dimensional matrix of 8-bit integers
    rgb = np.dstack((b, g, r)).astype(np.uint8)
    return rgb


def fold(v, size=8):
    step = size*size
    n = int(np.ceil(len(v) / step))
    print('%i folding into %i tiles (%i x %i)' % (len(v), n, size, size))

    n_i = int(len(v)**0.5)
    v_folded = []
    k = 0
    for i in range(0, n_i, size):
        for j in range(0, n_i, size):
            # i_end = min(i+step, len(v))
            size_i = min(size, n_i-i)
            size_j = min(size, n_i-j)
            col = []
            for _ in range(size_i):
                row = []
                for _ in range(size_j):
                    row.append(v[k])
                    k += 1
                col.append(row)
            v_folded.append(col)
    # for i in range(0, len(v), step):
    #     i_end = min(i+step, len(v))
    #     col = []
    #     for _ in range(size):
    #         row = []
    #         for _ in range(size):
    #             row.append(v[i])
    #             i += 1
    #         col.append(row)
    #     v_folded.append(col)

    return v_folded
    # if(n > 1):
    #     return fold(v_folded, 2)
    # else:
    #     return v_folded


def flatten(v, horizontal=False):
    if(isinstance(v, list)):
        if(horizontal):
            return np.hstack([flatten(elem, False) for elem in v])
        else:
            return np.vstack([flatten(elem, True) for elem in v])
    else:
        return v

# def tile(vec, i=0):
#     # step = size*size
#     n = len(vec)**0.5
#     d = n/2
#     print('super tiles (%i): %i x %i' % (i, n, n))
#     folded_vec
#     if(n1 > 1):
#         for x in range(0, int(n), d):
#             for y in range(0, int(n), d):
#                 tile(vec[j*step:(j+1)*step], i+1)


def export(filename, data):
    pixels = np.frombuffer(bytearray(data), dtype=np.uint16)
    print(len(pixels))
    # tile(data)

    nTiles = int(len(pixels)**0.5 / 8)

    v = [i for i in range(nTiles**2 * 8**2)]
    # tiles
    v = fold(v, size=2)
    v = fold(v, size=2)
    v = fold(v, size=2)
    # images
    v = fold(v, size=nTiles)

    # print(v)
    f = flatten(v[0], False)
    # print(f)

    img565 = pixels[f]
    img = rgb565to888(img565)
    cv2.imwrite(filename, img)


if(__name__ == '__main__'):
    with open('icon_48x48.raw', 'rb') as fp:
        # with open('icon_24x24.raw', 'rb') as fp:
        # data = fp.read()
        export('test.png', fp.read())
