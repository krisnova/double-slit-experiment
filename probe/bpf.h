/*
 * This file is part of The Double Slit Experiment (https://github.com/kris-nova/doubleslitexperiment).
 * Copyright (c) 2021 Kris Nóva <kris@nivenly.com>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *     ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
 *     ████╗  ██║██╔═████╗██║   ██║██╔══██╗
 *     ██╔██╗ ██║██║██╔██║██║   ██║███████║
 *     ██║╚██╗██║████╔╝██║╚██╗ ██╔╝██╔══██║
 *     ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
 *     ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
 */

#ifndef DOUBLE_SLIT_EXPERIMENT_BPF_H
#define DOUBLE_SLIT_EXPERIMENT_BPF_H

#define LAST_32_BITS(x) x & 0xFFFFFFFF
#define FIRST_32_BITS(x) x >> 32
#define DATA_SIZE_32 32
#define DATA_SIZE_64 64

#define DEBUG 1

#endif