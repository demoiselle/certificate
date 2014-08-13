package br.gov.frameworkdemoiselle.policy.engine.asn1.etsi;

import br.gov.frameworkdemoiselle.policy.engine.asn1.ASN1Object;
import java.util.Collection;

public class SkipCerts extends ASN1Object {

    private Collection<Integer> skipCerts;

    public Collection<Integer> getSkipCerts() {
        return skipCerts;
    }

    public void setSkipCerts(Collection<Integer> skipCerts) {
        this.skipCerts = skipCerts;
    }

}
