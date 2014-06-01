#include <stdio.h>
#include "ossl.h"

#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_GOST2001) && (OPENSSL_VERSION_NUMBER >= 0x01000000fL)

/* May be it can be deleted */
static VALUE gost_ec_instance(VALUE klass, EC_KEY *ec)
{
    EVP_PKEY *pkey;
    VALUE obj;

    if (!ec) {
    return Qfalse;
    }
    if (!(pkey = EVP_PKEY_new())) {
    return Qfalse;
    }
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec)) {
    EVP_PKEY_free(pkey);
    return Qfalse;
    }
    WrapPKey(klass, obj, pkey);

    return obj;
}

VALUE ossl_gost2001_new(EVP_PKEY *pkey)
{
    VALUE obj;

    if (!pkey) {
        obj = gost_ec_instance(cGost2001, EC_KEY_new());
    } else {
        if (EVP_PKEY_type(pkey->type) != NID_id_GostR3410_2001) {
            ossl_raise(rb_eTypeError, "Not a GOST R 34.10-2001 key!");
        }
        WrapPKey(cGost2001, obj, pkey);
    }
    if (obj == Qfalse) {
        ossl_raise(eGost2001Error, NULL);
    }

    return obj;
}


/*  call-seq:
 *     OpenSSL::PKey::Gost2001.new()
 *     OpenSSL::PKey::Gost2001.new(ec_key)
 *     OpenSSL::PKey::Gost2001.new(ec_group)
 *     OpenSSL::PKey::Gost2001.new("secp112r1")
 *     OpenSSL::PKey::Gost2001.new(pem_string)
 *     OpenSSL::PKey::Gost2001.new(pem_string [, pwd])
 *     OpenSSL::PKey::Gost2001.new(der_string)
 *
 *  See the OpenSSL documentation for:
 *     EC_KEY_*
 */
static VALUE ossl_gost2001_key_initialize(int argc, VALUE *argv, VALUE self)
{
    rb_call_super(argc, argv);
    EVP_PKEY *pkey;
    GetPKey(self, pkey);
    EC_KEY *ec = pkey->pkey.ec;
    fill_GOST2001_params(ec, EVP_PKEY_type(pkey->type));
}

void Init_ossl_gost2001()
{
    shfsjkbg_good();
    printf("Uh, oh, zer gut!");
#ifdef DONT_NEED_RDOC_WORKAROUND
    mOSSL = rb_define_module("OpenSSL");
    mPKey = rb_define_module_under(mOSSL, "PKey");
#endif

    eGost2001Error = rb_define_class_under(mPKey, "Gost2001Error", eECError);
    cGost2001 = rb_define_class_under(mPKey, "Gost2001", cEC);
    rb_define_method(cGost2001, "initialize", ossl_gost2001_key_initialize, -1);
}

#else /* defined NO_EC or defined NO_GOST2001 or OpenSSL is older than 1.0.0 */
void Init_ossl_gost2001();
{
phehehe_bzzz_noway();
printf("WHOA, OpenSSL IS BAD, NO WAY!");
}
#endif /* NO_EC or NO_GOST */
