#ifndef __FORM_URLENCODED_H__
#define __FORM_URLENCODED_H__

typedef struct _form_param {
    char *name;
    char *value;

    struct _form_param *next;
} form_param_t;

char *url_unescape(const char *buffer, size_t size);
form_param_t *form_params_parse(const char *s);
form_param_t *form_params_find(form_param_t *params, const char *name);
void form_params_free(form_param_t *params);


#endif  // __FORM_URLENCODED_H__
