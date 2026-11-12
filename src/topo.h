/* Topology file: "node <id> [name]" and "link <a> <b> <cost>" lines, '#' comments. */
#ifndef SPARROW_TOPO_H
#define SPARROW_TOPO_H

#include <stdint.h>

#define TOPO_MAX_LINKS 256

typedef struct {
    uint16_t a, b, cost;
} topo_link;

typedef struct {
    int nlinks;
    topo_link links[TOPO_MAX_LINKS];
} topo_t;

int topo_load(topo_t *t, const char *path);

#endif
