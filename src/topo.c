#include "topo.h"

#include <stdio.h>
#include <string.h>

#include "proto.h"

int topo_load(topo_t *t, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    t->nlinks = 0;
    int rc = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned a, b, c;
        if (line[0] == '#' || line[0] == '\n' || !strncmp(line, "node", 4)) continue;
        if (sscanf(line, "link %u %u %u", &a, &b, &c) == 3) {
            if (a == 0 || b == 0 || a >= MAX_ROUTERS || b >= MAX_ROUTERS || a == b || c == 0 ||
                c > 0xFFFF || t->nlinks >= TOPO_MAX_LINKS) { rc = -1; break; }
            t->links[t->nlinks].a = (uint16_t)a;
            t->links[t->nlinks].b = (uint16_t)b;
            t->links[t->nlinks].cost = (uint16_t)c;
            t->nlinks++;
        } else { rc = -1; break; }
    }
    fclose(f);
    return rc;
}
