package br.gov.frameworkdemoiselle.policy.engine.asn1.icpb;

import br.gov.frameworkdemoiselle.policy.engine.asn1.ASN1Object;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;

public class PoliciesDigest extends ASN1Object {

    private OtherHashAlgAndValue textualPolicyDigest;
    private OtherHashAlgAndValue asn1PolicyDigest;
    private OtherHashAlgAndValue xmlPolicyDigest;

    enum TAG {

        textualPolicyDigest(0),
        asn1PolicyDigest(1),
        xmlPolicyDigest(2);

        int value;

        private TAG(int value) {
            this.value = value;
        }

        public static TAG getTag(int value) {
            for (TAG tag : TAG.values()) {
                if (tag.value == value) {
                    return tag;
                }
            }
            return null;
        }
    }

}
