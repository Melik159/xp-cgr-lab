#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Tcdefs.h"
#include "Common/Fat.h"
#include "Common/Random.h"

static const unsigned char g_volume_id[4] = { 0x83, 0x7b, 0xfc, 0xfb };
static int g_rand_calls = 0;

BOOL RandgetBytes (unsigned char *buf, int len, BOOL forceSlowPoll)
{
    if (buf == NULL || len != 4 || forceSlowPoll != FALSE || g_rand_calls != 0)
        return FALSE;

    memcpy (buf, g_volume_id, 4);
    g_rand_calls++;
    return TRUE;
}

int main (void)
{
    fatparams ft;
    unsigned char boot[512];
    FILE *f;

    memset (&ft, 0, sizeof (ft));
    memset (boot, 0, sizeof (boot));

    /* Exact TCFormatVolume FAT parameters for RUN3 before GetFatParams(). */
    ft.num_sectors = 32256;
    ft.cluster_size = 0;  /* default cluster size */
    memcpy (ft.volume_name, "NO NAME    ", 11);

    GetFatParams (&ft);

    if (ft.cluster_size != 1 ||
        ft.size_fat != 16 ||
        ft.reserved != 2 ||
        ft.fat_length != 125 ||
        ft.dir_entries != 512 ||
        ft.fats != 2 ||
        ft.sector_size != 512)
        return 20;

    PutBoot (&ft, boot);

    if (g_rand_calls != 1)
        return 21;

    f = fopen ("putboot-source-replay.bin", "wb");
    if (!f)
        return 22;

    if (fwrite (boot, 1, sizeof (boot), f) != sizeof (boot))
    {
        fclose (f);
        return 23;
    }

    if (fclose (f) != 0)
        return 24;

    return 0;
}
