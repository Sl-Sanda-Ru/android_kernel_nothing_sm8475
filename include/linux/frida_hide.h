/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FRIDA_HIDE_H
#define _LINUX_FRIDA_HIDE_H

#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>

/* True when the *calling* task's executable is frida-server itself.
 * Used to bypass all hiding logic for frida-server's own syscalls so it
 * can read /proc/self/maps, set its own thread names, and bind its ports
 * without being lied to (which caused libstdc++ out_of_range aborts). */
static inline bool frida_hide_current_is_frida(void)
{
	struct mm_struct *mm;
	struct file *exe;
	char buf[128], *p;
	bool ret = false;

	mm = current->mm;
	if (!mm)
		return false;
	exe = get_mm_exe_file(mm);
	if (!exe)
		return false;
	p = d_path(&exe->f_path, buf, sizeof(buf));
	if (!IS_ERR(p))
		ret = strstr(p, "frida-server") != NULL ||
		      strstr(p, "re.frida.server") != NULL;
	fput(exe);
	return ret;
}

static const char * const __frida_hide_needles[] = {
	"frida",
	"gum-js-loop",
	"gmain",
	"gdbus",
	"linjector",
	"pool-frida",
	"re.frida.server",
	"memfd:jit-cache",
	"memfd:frida",
	":6982 ",	/* frida-server default TCP 27042 */
	":6983 ",	/* frida-server default TCP 27043 */
};

static inline bool frida_hide_seq_line(struct seq_file *m, size_t start)
{
	size_t len;
	int i;

	if (!m || !m->buf || m->count <= start || m->count > m->size)
		return false;
	if (frida_hide_current_is_frida())
		return false;

	len = m->count - start;
	for (i = 0; i < ARRAY_SIZE(__frida_hide_needles); i++) {
		if (strnstr(m->buf + start, __frida_hide_needles[i], len)) {
			m->count = start;
			return true;
		}
	}
	return false;
}

static const char * const __frida_hide_tracer_needles[] = {
	"frida",
	"gum-js-loop",
	"gmain",
	"gdb",		/* gdb, gdbserver */
	"lldb",		/* lldb, lldb-server */
	"strace",
	"ltrace",
	"ptrace",
};

static inline bool frida_hide_is_tracer(struct task_struct *t)
{
	int i;

	if (!t)
		return false;
	if (t->group_leader == current->group_leader)
		return false;
	if (frida_hide_current_is_frida())
		return false;
	for (i = 0; i < ARRAY_SIZE(__frida_hide_tracer_needles); i++) {
		if (strnstr(t->comm, __frida_hide_tracer_needles[i],
			    sizeof(t->comm)))
			return true;
	}
	return false;
}

static const char * const __frida_hide_comm_needles[] = {
	"gum-js-loop",
	"gmain",
	"gdbus",
	"pool-frida",
	"frida",
};

/* If tcomm looks like a frida worker thread, replace with a benign name. */
static inline void frida_hide_mask_comm(char *tcomm, size_t sz)
{
	int i;

	if (!tcomm || sz == 0)
		return;
	if (frida_hide_current_is_frida())
		return;
	for (i = 0; i < ARRAY_SIZE(__frida_hide_comm_needles); i++) {
		if (strnstr(tcomm, __frida_hide_comm_needles[i], sz)) {
			strscpy(tcomm, "Binder:0_1", sz);
			return;
		}
	}
}

/* True if dst port is a default frida-server listener. */
static inline bool frida_hide_port_blocked(__be16 be_port)
{
	unsigned short p = ntohs(be_port);
	if (frida_hide_current_is_frida())
		return false;
	return p == 27042 || p == 27043;
}

/* True if the resolved fd symlink target looks like a frida injector artifact.
 * Kept narrow ("linjector", "re.frida.server") to avoid false positives on
 * legitimate user paths that happen to contain "frida". */
static inline bool frida_hide_path_hidden(const char *path)
{
	if (!path)
		return false;
	if (frida_hide_current_is_frida())
		return false;
	return strstr(path, "linjector") != NULL ||
	       strstr(path, "re.frida.server") != NULL;
}

#endif /* _LINUX_FRIDA_HIDE_H */
