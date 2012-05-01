/*
 * imagex.c
 *
 * Use wimlib to create, modify, extract, mount, unmount, or display information
 * about a WIM file
 *
 * Copyright (C) 2012 Eric Biggers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "wimlib.h"
#include "config.h"
#include <getopt.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

#define swap(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); \
				a = __b; b = __a; })

#define for_opt(c, opts) while ((c = getopt_long_only(argc, (char**)argv, "", \
				opts, NULL)) != -1)

enum imagex_op_type {
	APPEND,
	APPLY,
	CAPTURE,
	DELETE,
	DIR,
	EXPORT,
	INFO,
	MOUNT,
	MOUNTRW,
	UNMOUNT,
};

static const char *path_basename(const char *path)
{
	const char *p = path;
	while (*p)
		p++;
	p--;

	/* Trailing slashes. */
	while ((p != path - 1) && *p == '/')
		p--;

	while ((p != path - 1) && *p != '/')
		p--;

	return p + 1;
}


static const char *usage_strings[] = {
[APPEND] = 
"    imagex append DIRECTORY WIMFILE [\"IMAGE_NAME\"] [\"DESCRIPTION\"] [--boot]\n"
"        [--check] [--config CONFIG_FILE] [--flags EDITIONID] [--verify]\n",
[APPLY] = 
"    imagex apply WIMFILE [IMAGE_NUM | IMAGE_NAME | all] DIRECTORY [--check]\n"
"        [--verify] [--hardlink] [--symlink] [--verbose]\n",
[CAPTURE] = 
"    imagex capture DIRECTORY WIMFILE [\"IMAGE_NAME\"] [\"DESCRIPTION\"]\n"
"        [--boot] [--check] [--compress[=TYPE]] [--config CONFIG_FILE]\n"
"        [--flags \"EditionID\"] [--norpfix] [--verify] [--verbose]\n",
[DELETE] = 
"    imagex delete WIMFILE (IMAGE_NUM | IMAGE_NAME | all) [--check]\n",
[DIR] = 
"    imagex dir WIMFILE (IMAGE_NUM | IMAGE_NAME | \"all\")\n",
[EXPORT] = 
"    imagex export SRC_WIMFILE (SRC_IMAGE_NUM | SRC_IMAGE_NAME | all ) \n"
"        DEST_WIMFILE [\"DEST_IMAGE_NAME\"] [\"DEST_IMAGE_DESCRIPTION\"]\n"
"        [--boot] [--check] [--compress[=TYPE]]\n",
[INFO] = 
"    imagex info WIMFILE [IMAGE_NUM | IMAGE_NAME] [NEW_NAME]\n"
"        [NEW_DESC] [--boot] [--check] [--header] [--lookup-table]\n"
"        [--xml] [--extract-xml FILE] [--metadata]\n",
[MOUNT] = 
"    imagex mount WIMFILE (IMAGE_NUM | IMAGE_NAME) DIRECTORY\n"
"        [--check] [--debug]\n",
[MOUNTRW] = 
"    imagex mountrw WIMFILE [IMAGE_NUM | IMAGE_NAME] DIRECTORY\n"
"        [--check] [--debug]\n",
[UNMOUNT] = 
"    imagex unmount DIRECTORY [--commit] [--check]\n",
};

static const struct option common_options[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'v'},
	{NULL, 0, NULL, 0},
};

static const struct option append_options[] = {
	{"boot",   no_argument,       NULL, 'b'},
	{"check",  no_argument,       NULL, 'c'},
	{"config", required_argument, NULL, 'C'},
	{"flags",    required_argument, NULL, 'f'},
	{"verify", no_argument,       NULL, 'V'},
	{NULL, 0, NULL, 0},
};
static const struct option apply_options[] = {
	{"check",    no_argument,       NULL, 'c'},
	{"verify",   no_argument,       NULL, 'V'},
	{"hardlink", no_argument,       NULL, 'h'},
	{"symlink",  no_argument,       NULL, 's'},
	{"verbose",  no_argument,       NULL, 'v'},
	{NULL, 0, NULL, 0},
};
static const struct option capture_options[] = {
	{"boot",     no_argument,       NULL, 'b'},
	{"check",    no_argument,       NULL, 'c'},
	{"compress", optional_argument, NULL, 'x'},
	{"config",   required_argument, NULL, 'C'},
	{"flags",    required_argument, NULL, 'f'},
	{"norpfix",  no_argument,       NULL, 'n'},
	{"verify",   no_argument,       NULL, 'V'},
	{"verbose",   no_argument,       NULL, 'v'},
	{NULL, 0, NULL, 0},
};
static const struct option delete_options[] = {
	{"check", no_argument, NULL, 'c'},
	{NULL, 0, NULL, 0},
};

static const struct option export_options[] = {
	{"boot",       no_argument, NULL, 'b'},
	{"check",      no_argument , NULL, 'c'},
	{"compress",   optional_argument, NULL, 'x'},
	{NULL, 0, NULL, 0},
};

static const struct option info_options[] = {
	{"boot",         no_argument, NULL, 'b'},
	{"check",        no_argument, NULL, 'c'},
	{"header",       no_argument, NULL, 'h'},
	{"lookup-table", no_argument, NULL, 'l'},
	{"xml",          no_argument, NULL, 'x'},
	{"extract-xml",  required_argument, NULL, 'X'},
	{"metadata",     no_argument, NULL, 'm'},
	{NULL, 0, NULL, 0},
};
static const struct option mount_options[] = {
	{"check", no_argument, NULL, 'c'},
	{"debug", no_argument, NULL, 'd'},
	{NULL, 0, NULL, 0},
};

static const struct option unmount_options[] = {
	{"commit", no_argument, NULL, 'c'},
	{"check", no_argument, NULL, 'C'},
	{NULL, 0, NULL, 0},
};


/* Print formatted error message to stderr. */
static void imagex_error(const char *format, ...)
{
	va_list va;
	va_start(va, format);
	fputs("ERROR: ", stderr);
	vfprintf(stderr, format, va);
	va_end(va);
}


static inline void version()
{
	static const char *s = 
	"imagex (" PACKAGE ") " PACKAGE_VERSION "\n"
	"Copyright (C) 2012 Eric Biggers\n"
	"License GPLv3+; GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.\n"
	"\n"
	"Report bugs to "PACKAGE_BUGREPORT".\n";
	fputs(s, stdout);
}

static inline void usage(int cmd)
{
	puts("IMAGEX: Usage:");
	fputs(usage_strings[cmd], stdout);
}

static void usage_all()
{
	puts("IMAGEX: Usage:");
	for (int i = 0; i < ARRAY_LEN(usage_strings); i++)
		fputs(usage_strings[i], stdout);
	static const char *extra = 
"    imagex --help\n"
"    imagex --version\n"
"\n"
"    The compression TYPE may be \"maximum\", \"fast\", or \"none\".\n"
	;
	fputs(extra, stdout);
}

static int verify_image_exists(int image)
{
	if (image == WIM_NO_IMAGE) {
		imagex_error("Not a valid image!\n");
		return WIMLIB_ERR_INVALID_IMAGE;
	}
	return 0;
}

static int verify_image_is_single(int image)
{
	if (image == WIM_ALL_IMAGES) {
		imagex_error("Cannot specify all images for this action!\n");
		return WIMLIB_ERR_INVALID_IMAGE;
	}
	return 0;
}

static int verify_image_exists_and_is_single(int image)
{
	int ret;
	ret = verify_image_exists(image);
	if (ret == 0)
		ret = verify_image_is_single(image);
	return ret;
}

static int get_compression_type(const char *optarg)
{
	if (!optarg)
		return WIM_COMPRESSION_TYPE_LZX;
	if (strcasecmp(optarg, "maximum") == 0 || strcasecmp(optarg, "lzx") == 0)
		return WIM_COMPRESSION_TYPE_LZX;
	else if (strcasecmp(optarg, "fast") == 0 || strcasecmp(optarg, "xpress") == 0)
		return WIM_COMPRESSION_TYPE_XPRESS;
	else if (strcasecmp(optarg, "none") == 0)
		return WIM_COMPRESSION_TYPE_NONE;
	else {
		imagex_error("Invalid compression type `%s'! Must be "
				"\"maximum\", \"fast\", or \"none\".\n", 
				optarg);
		return WIM_COMPRESSION_TYPE_INVALID;
	}
}

static int imagex_append(int argc, const char **argv)
{
	int c;
	const char *flags_element = NULL;
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	int add_image_flags = 0;
	int write_flags = WIMLIB_WRITE_FLAG_SHOW_PROGRESS;
	const char *dir;
	const char *wimfile;
	const char *name;
	const char *desc;
	WIMStruct *w;
	int ret;

	for_opt(c, append_options) {
		switch (c) {
		case 'b':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_BOOT;
			break;
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case 'C':
			/*config = optarg;*/
			break;
		case 'f':
			flags_element = optarg;
			break;
		case 'V':
			/* verify */
			break;
		default:
			usage(APPEND);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 2 || argc > 4) {
		usage(APPEND);
		return -1;
	}
	dir     = argv[0];
	wimfile = argv[1];
	name    = (argc >= 3) ? argv[2] : path_basename(dir);
	desc    = (argc >= 4) ? argv[3] : NULL;

	ret = wimlib_open_wim(wimfile, open_flags, &w);
	if (ret != 0)
		return ret;

	ret = wimlib_add_image(w, dir, name, desc, 
			       flags_element, add_image_flags);
	if (ret != 0)
		goto done;
	ret = wimlib_overwrite(w, write_flags);
done:
	wimlib_free(w);
	return ret;
}

/* Extract one image, or all images, from a WIM file into a directory. */
static int imagex_apply(int argc, const char **argv)
{
	int c;
	int link_type = WIM_LINK_TYPE_NONE;
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	bool verbose = false;
	int image;
	int num_images;
	WIMStruct *w;
	int ret;
	const char *wimfile;
	const char *dir;
	const char *image_num_or_name;

	for_opt(c, apply_options) {
		switch (c) {
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			break;
		case 'V':
			/* verify */
			break;
		case 'h':
			link_type = WIM_LINK_TYPE_HARD;
			break;
		case 's':
			link_type = WIM_LINK_TYPE_SYMBOLIC;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			usage(APPLY);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2 && argc != 3) {
		usage(APPLY);
		return -1;
	}

	wimfile = argv[0];
	if (argc == 2) {
		image_num_or_name =  "1";
		dir = argv[1];
	} else {
		image_num_or_name = argv[1];
		dir = argv[2];
	}

	ret = wimlib_open_wim(wimfile, open_flags, &w);
	if (ret != 0)
		return ret;

	image = wimlib_resolve_image(w, image_num_or_name);
	ret = verify_image_exists(image);
	if (ret != 0)
		goto done;

	num_images = wimlib_get_num_images(w);
	if (argc == 2 && num_images != 1) {
		imagex_error("`%s' contains %d images; Please select one "
				"(or all).\n", wimfile, num_images);
		usage(APPLY);
		ret = -1;
		goto done;
	}
	ret = wimlib_set_output_dir(w, dir);
	if (ret != 0)
		goto done;
	wimlib_set_verbose(w, verbose);
	wimlib_set_link_type(w, link_type);
	ret = wimlib_extract_image(w, image);
done:
	wimlib_free(w);
	return ret;
}


/* Create a WIM file from a directory. */
static int imagex_capture(int argc, const char **argv)
{
	int c;
	int add_image_flags = 0;
	int write_flags = WIMLIB_WRITE_FLAG_SHOW_PROGRESS;
	int compression_type = WIM_COMPRESSION_TYPE_NONE;
	const char *flags_element    = NULL;
	bool verbose         = false;
	const char *dir;
	const char *wimfile;
	const char *name;
	const char *desc;
	WIMStruct *w;
	int ret;

	for_opt(c, capture_options) {
		switch (c) {
		case 'b':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_BOOT;
			break;
		case 'c':
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case 'x':
			compression_type = get_compression_type(optarg);
			if (compression_type == WIM_COMPRESSION_TYPE_INVALID)
				return -1;
			break;
		case 'C':
			/*config = optarg;*/
			break;
		case 'f':
			flags_element = optarg;
			break;
		case 'n':
			/*norpfix = true;*/
			break;
		case 'v':
			verbose = true;
			break;
		case 'V':
			/*verify = true;*/
			break;
		default:
			usage(CAPTURE);
			return -1;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc < 2 || argc > 4) {
		usage(CAPTURE);
		return -1;
	}
	dir     = argv[0];
	wimfile = argv[1];
	name    = (argc >= 3) ? argv[2] : dir;
	desc    = (argc >= 4) ? argv[3] : NULL;

	ret = wimlib_create_new_wim(compression_type, &w);
	if (ret != 0)
		return ret;

	wimlib_set_verbose(w, verbose);

	ret = wimlib_add_image(w, dir, name, desc, flags_element, 
			       add_image_flags);
	if (ret != 0) {
		imagex_error("Failed to add the image `%s'!\n", dir);
		goto done;
	}

	ret = wimlib_write(w, wimfile, WIM_ALL_IMAGES, write_flags);
	if (ret != 0)
		imagex_error("Failed to write the WIM file `%s'!\n", wimfile);
done:
	wimlib_free(w);
	return ret;
}

/* Remove image(s) from a WIM. */
static int imagex_delete(int argc, const char **argv)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	int write_flags = WIMLIB_WRITE_FLAG_SHOW_PROGRESS;
	const char *wimfile;
	const char *image_num_or_name;
	WIMStruct *w;
	int image;
	int ret;

	for_opt(c, delete_options) {
		switch (c) {
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		default:
			usage(DELETE);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2) {
		if (argc < 1)
			imagex_error("Must specify a WIM file!\n");
		if (argc < 2)
			imagex_error("Must specify an image!\n");
		usage(DELETE);
		return -1;
	}
	wimfile = argv[0];
	image_num_or_name = argv[1];

	ret = wimlib_open_wim(wimfile, open_flags, &w);
	if (ret != 0)
		return ret;

	image = wimlib_resolve_image(w, image_num_or_name);

	ret = verify_image_exists(image);
	if (ret != 0)
		goto done;

	ret = wimlib_delete_image(w, image);
	if (ret != 0) {
		imagex_error("Failed to delete image from `%s'!\n",
						wimfile);
		goto done;
	}

	ret = wimlib_overwrite(w, write_flags);
	if (ret != 0) {
		imagex_error("Failed to write the file `%s' with image "
				"deleted!\n", wimfile);
	}
done:
	wimlib_free(w);
	return ret;
}

/* Print the files contained in an image(s) in a WIM file. */
static int imagex_dir(int argc, const char **argv)
{
	const char *wimfile;
	WIMStruct *w;
	int image;
	int ret;
	int num_images;

	if (argc < 2) {
		imagex_error("Must specify a WIM file!\n");
		usage(DIR);
		return -1;
	}
	if (argc > 3) {
		imagex_error("Too many arguments!\n");
		usage(DIR);
		return -1;
	}

	wimfile = argv[1];
	ret = wimlib_open_wim(wimfile, 0, &w);
	if (ret != 0)
		return ret;

	if (argc == 3) {
		image = wimlib_resolve_image(w, argv[2]);
		ret = verify_image_exists(image);
		if (ret != 0)
			goto done;
	} else {
		/* Image was not specified.  If the WIM only contains one image,
		 * choose that one; otherwise, print an error. */
		num_images = wimlib_get_num_images(w);
		if (num_images != 1) {
			imagex_error("The file `%s' contains %d images; Please "
					"select one.\n", wimfile, num_images);
			usage(DIR);
			ret = -1;
			goto done;
		}
		image = 1;
	}

	ret = wimlib_print_files(w, image);
done:
	wimlib_free(w);
	return ret;
}

/* Exports one, or all, images from a WIM file to a new WIM file or an existing
 * WIM file. */
static int imagex_export(int argc, const char **argv)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	int export_flags = 0;
	int write_flags = WIMLIB_WRITE_FLAG_SHOW_PROGRESS;
	int compression_type = WIM_COMPRESSION_TYPE_NONE;
	bool compression_type_specified = false;
	const char *src_wimfile;
	const char *src_image_num_or_name;
	const char *dest_wimfile;
	const char *dest_name;
	const char *dest_desc;
	WIMStruct *src_w = NULL;
	WIMStruct *dest_w = NULL;
	int ret;
	int image;
	struct stat stbuf;
	bool wim_is_new;

	for_opt(c, export_options) {
		switch (c) {
		case 'b':
			export_flags |= WIMLIB_EXPORT_FLAG_BOOT;
			break;
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case 'x':
			compression_type = get_compression_type(optarg);
			if (compression_type == WIM_COMPRESSION_TYPE_INVALID)
				return -1;
			compression_type_specified = true;
			break;
		default:
			usage(EXPORT);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 3 || argc > 5) {
		usage(EXPORT);
		return -1;
	}
	src_wimfile           = argv[0];
	src_image_num_or_name = argv[1];
	dest_wimfile          = argv[2];
	dest_name             = (argc >= 4) ? argv[3] : NULL;
	dest_desc             = (argc >= 5) ? argv[4] : NULL;
	ret = wimlib_open_wim(src_wimfile, open_flags, &src_w);
	if (ret != 0)
		return ret;

	/* Determine if the destination is an existing file or not.  
	 * If so, we try to append the exported image(s) to it; otherwise, we
	 * create a new WIM containing the exported image(s). */
	if (stat(dest_wimfile, &stbuf) == 0) {
		wim_is_new = false;
		/* Destination file exists. */
		if (!S_ISREG(stbuf.st_mode)) {
			imagex_error("`%s' is not a regular file!\n",
					dest_wimfile);
			goto done;
		}
		ret = wimlib_open_wim(dest_wimfile, open_flags, &dest_w);
		if (ret != 0)
			goto done;

		if (compression_type_specified && compression_type != 
				wimlib_get_compression_type(dest_w)) {
			imagex_error("Cannot specify a compression type that is "
					"not the same as that used in the "
					"destination WIM!\n");
			goto done;
		}
		compression_type = wimlib_get_compression_type(dest_w);
	} else {
		wim_is_new = true;
		/* dest_wimfile is not an existing file, so create a new WIM. */
		if (errno == ENOENT) {
			ret = wimlib_create_new_wim(compression_type, &dest_w);
			if (ret != 0)
				goto done;
		} else {
			imagex_error("Cannot stat file `%s': %m\n",
						dest_wimfile);
			goto done;
		}
	}

	image = wimlib_resolve_image(src_w, src_image_num_or_name);
	ret = verify_image_exists(image);
	if (ret != 0)
		goto done;

	ret = wimlib_export_image(src_w, image, dest_w, dest_name, dest_desc, 
				  export_flags);
	if (ret != 0)
		goto done;


	if (wim_is_new)
		ret = wimlib_write(dest_w, dest_wimfile, WIM_ALL_IMAGES, 
				   write_flags);
	else
		ret = wimlib_overwrite(dest_w, write_flags);
done:
	wimlib_free(src_w);
	wimlib_free(dest_w);
	return ret;
}

/* Prints information about a WIM file; also can mark an image as bootable,
 * change the name of an image, or change the description of an image. */
static int imagex_info(int argc, const char **argv)
{
	int c;
	bool boot         = false;
	bool check        = false;
	bool header       = false;
	bool lookup_table = false;
	bool xml          = false;
	bool metadata     = false;
	bool short_header = true;
	const char *xml_out_file = NULL;
	const char *wimfile;
	const char *image_num_or_name = "all";
	const char *new_name = NULL;
	const char *new_desc = NULL;
	WIMStruct *w;
	FILE *fp;
	int image;
	int ret;

	for_opt(c, info_options) {
		switch (c) {
		case 'b':
			boot = true;
			break;
		case 'c':
			check = true;
			break;
		case 'h':
			header = true;
			short_header = false;
			break;
		case 'l':
			lookup_table = true;
			short_header = false;
			break;
		case 'x':
			xml = true;
			short_header = false;
			break;
		case 'X':
			xml_out_file = optarg;
			short_header = false;
			break;
		case 'm':
			metadata = true;
			short_header = false;
			break;
		default:
			usage(INFO);
			return -1;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc == 0 || argc > 4) {
		usage(INFO);
		return -1;
	}
	wimfile = argv[0];
	if (argc > 1) {
		image_num_or_name = argv[1];
		if (argc > 2) {
			new_name = argv[2];
			if (argc > 3) {
				new_desc = argv[3];
			} 
		}
	}

	ret = wimlib_open_wim(wimfile, 
			      check ? 
			      	WIMLIB_OPEN_FLAG_CHECK_INTEGRITY |
					WIMLIB_OPEN_FLAG_SHOW_PROGRESS
				: 0, 
			      &w);
	if (ret != 0)
		return ret;

	image = wimlib_resolve_image(w, image_num_or_name);
	if (image == WIM_NO_IMAGE && strcmp(image_num_or_name, "0") != 0) {
		imagex_error("The image `%s' does not exist!\n", 
						image_num_or_name);
		if (boot)
			imagex_error("If you would like to set the boot "
					"index to 0, specify image \"0\" with "
					"the --boot flag.\n");
		ret = WIMLIB_ERR_INVALID_IMAGE;
		goto done;
	}

	if (image == WIM_ALL_IMAGES && wimlib_get_num_images(w) > 1) {
		if (boot) {
			imagex_error("Cannot specify the --boot flag "
					"without specifying a specific "
					"image in a multi-image WIM!\n");
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto done;
		}
		if (new_name) {
			imagex_error("Cannot specify the NEW_NAME "
					"without specifying a specific "
					"image in a multi-image WIM!\n");
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto done;
		}
	}

	/* Operations that print information are separated from operations that
	 * recreate the WIM file. */
	if (!new_name && !boot) {

		if (image == WIM_NO_IMAGE) {
			imagex_error("`%s' is not a valid image!\n", 
					image_num_or_name);
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto done;
		}

		if (image == WIM_ALL_IMAGES && short_header)
			wimlib_print_wim_information(w);

		if (header)
			wimlib_print_header(w);

		if (lookup_table)
			wimlib_print_lookup_table(w);

		if (xml) {
			ret = wimlib_extract_xml_data(w, stdout);
			if (ret != 0)
				goto done;
		}

		if (xml_out_file) {
			fp = fopen(xml_out_file, "wb");
			if (!fp) {
				imagex_error("Failed to open the file `%s' for "
						"writing: %m\n", xml_out_file);
				goto done;
			}
			ret = wimlib_extract_xml_data(w, fp);
			if (fclose(fp) != 0) {
				imagex_error("Failed to close the "
						"file `%s': %m\n",
						xml_out_file);
				goto done;
			}

			if (ret != 0)
				goto done;
		}

		if (short_header)
			wimlib_print_available_images(w, image);

		if (metadata) {
			ret = wimlib_print_metadata(w, image);
			if (ret != 0)
				goto done;
		}
	} else {
		if (image == WIM_ALL_IMAGES)
			image = 1;

		if (image == WIM_NO_IMAGE && new_name) {
			imagex_error("Cannot specify new_name (`%s') when "
					"using image 0!\n");
			return -1;
		}

		if (boot) {
			if (image == wimlib_get_boot_idx(w)) {
				printf("Image %d is already marked as "
						"bootable.\n", image);
				boot = false;
			} else {
				printf("Marking image %d as bootable.\n", 
								image);
				wimlib_set_boot_idx(w, image);
			}
		}
		if (new_name) {
			if (strcmp(wimlib_get_image_name(w, image), 
						new_name) == 0) {
				printf("Image %d is already named \"%s\".\n",
						image, new_name);
				new_name = NULL;
			} else {
				printf("Changing the name of image %d to \"%s\".\n",
						image, new_name);
				ret = wimlib_set_image_name(w, image, new_name);
				if (ret != 0)
					goto done;
			}
		}
		if (new_desc) {
			const char *old_desc;
			old_desc = wimlib_get_image_description(w, image);
			if (old_desc && strcmp(old_desc, new_desc) == 0) {
				printf("The description of image %d is already "
						"\"%s\".\n", image, new_desc);
				new_desc = NULL;
			} else {
				printf("Changing the description of image %d "
						"to \"%s\".\n", image, new_desc);
				ret = wimlib_set_image_descripton(w, image, 
								  new_desc);
				if (ret != 0)
					goto done;
			}
		}

		/* Only call wimlib_overwrite_xml_and_header() if something
		 * actually needs to be changed. */
		if (boot || new_name || new_desc || 
				check != wimlib_has_integrity_table(w)) {

			ret = wimlib_overwrite_xml_and_header(w, check ? 
					WIMLIB_WRITE_FLAG_CHECK_INTEGRITY | 
					WIMLIB_WRITE_FLAG_SHOW_PROGRESS : 0);
		} else {
			printf("The file `%s' was not modified because nothing "
					"needed to be done.\n", wimfile);
			ret = 0;
		}
	}

done:
	wimlib_free(w);
	return ret;
}

/* Mounts an image using a FUSE mount. */
static int imagex_mount_rw_or_ro(int argc, const char **argv)
{
	bool ro;
	int c;
	int mount_flags = 0;
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	const char *wimfile;
	const char *dir;
	WIMStruct *w;
	int image;
	int num_images;
	int ret;

	if (strcmp(argv[0], "mountrw") == 0)
		mount_flags |= WIMLIB_MOUNT_FLAG_READWRITE;
	for_opt(c, mount_options) {
		switch (c) {
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			break;
		case 'd':
			mount_flags |= WIMLIB_MOUNT_FLAG_DEBUG;
			break;
		default:
			usage(ro ? MOUNT : MOUNTRW);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2 && argc != 3) {
		usage(ro ? MOUNT : MOUNTRW);
		return -1;
	}

	wimfile = argv[0];

	ret = wimlib_open_wim(wimfile, open_flags, &w);
	if (ret != 0)
		return ret;

	if (argc == 2) {
		image = 1;
		num_images = wimlib_get_num_images(w);
		if (num_images != 1) {
			imagex_error("The file `%s' contains %d images; Please "
					"select one.\n", wimfile, num_images);
			usage(ro ? MOUNT : MOUNTRW);
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto done;
		}
		dir = argv[1];
	} else {
		image = wimlib_resolve_image(w, argv[1]);
		dir = argv[2];
	}

	ret = verify_image_exists_and_is_single(image);
	if (ret != 0)
		goto done;

	ret = wimlib_mount(w, image, dir, mount_flags);
	if (ret != 0) {
		imagex_error("Failed to mount image %d from `%s' on `%s'!\n",
				image, wimfile, dir);

	}
done:
	wimlib_free(w);
	return ret;
}

/* Unmounts an image. */
static int imagex_unmount(int argc, const char **argv)
{
	int c;
	int unmount_flags = 0;
	int ret;

	for_opt(c, unmount_options) {
		switch (c) {
		case 'c':
			unmount_flags |= WIMLIB_UNMOUNT_FLAG_COMMIT;
			break;
		case 'C':
			unmount_flags |= WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY;
			break;
		default:
			usage(UNMOUNT);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1) {
		usage(UNMOUNT);
		return -1;
	}

	ret = wimlib_unmount(argv[0], unmount_flags);
	if (ret != 0)
		imagex_error("Failed to unmount `%s'!\n", argv[0]);
	return ret;
}

struct imagex_command {
	const char *name;
	int (*func)(int , const char **);
	int cmd;
};

static struct imagex_command imagex_commands[] = {
	{"append",  imagex_append,	   APPEND},
	{"apply",   imagex_apply,   	   APPLY},
	{"capture", imagex_capture,	   CAPTURE},
	{"delete",  imagex_delete,	   DELETE},
	{"dir",     imagex_dir,		   DIR},
	{"export",  imagex_export,	   EXPORT},
	{"info",    imagex_info,	   INFO},
	{"mount",   imagex_mount_rw_or_ro, MOUNT},
	{"mountrw", imagex_mount_rw_or_ro, MOUNTRW},
	{"unmount", imagex_unmount,	   UNMOUNT},
};

#define for_imagex_command(p) for (p = &imagex_commands[0]; \
		p != &imagex_commands[ARRAY_LEN(imagex_commands)]; p++)

static void help_or_version(int argc, const char **argv)
{
	int i;
	const char *p;
	struct imagex_command *cmd;

	for (i = 1; i < argc; i++) {
		p = argv[i];
		if (*p == '-')
			p++;
		else
			continue;
		if (*p == '-')
			p++;
		if (strcmp(p, "help") == 0 || (*p == '?' && *(p + 1) == '\0')) {
			for_imagex_command(cmd) {
				if (strcmp(cmd->name, argv[1]) == 0) {
					usage(cmd->cmd);
					exit(0);
				}
			}
			usage_all();
			exit(0);
		}
		if (strcmp(p, "version") == 0) {
			version();
			exit(0);
		}
	}
}


int main(int argc, const char **argv)
{
	struct imagex_command *cmd;
	int ret;

	if (argc < 2) {
		imagex_error("No command specified!\n");
		usage_all();
		return 1;
	}

	help_or_version(argc, argv);
	argc--;
	argv++;

	wimlib_set_print_errors(true);

	for_imagex_command(cmd) {
		if (strcmp(cmd->name, *argv) == 0) {
			ret = cmd->func(argc, argv);
			if (ret > 0) {
				imagex_error("Exiting with error code %d:\n"
						"       %s.\n", ret, 
						wimlib_get_error_string(ret));
			}
			return ret;
		}
	}

	imagex_error("Unrecognized command: `%s'\n", argv[0]);
	usage_all();
	return 1;
}
