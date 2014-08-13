package br.gov.frameworkdemoiselle.policy.engine.asn1.etsi;

import br.gov.frameworkdemoiselle.policy.engine.asn1.ASN1Object;
import java.util.ArrayList;
import java.util.Collection;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class PathLenConstraint extends ASN1Object {

    private Collection<ObjectIdentifier> pathLenConstraints;

    public Collection<ObjectIdentifier> getPathLenConstraints() {
        return pathLenConstraints;
    }

    public void setPathLenConstraints(
            Collection<ObjectIdentifier> pathLenConstraints) {
        this.pathLenConstraints = pathLenConstraints;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        DERTaggedObject derTaggedObject = (DERTaggedObject) derObject;
        DERSequence derSequence = (DERSequence) derTaggedObject.getObject();
        int total = derSequence.size();
        for (int i = 0; i < total; i++) {
            ObjectIdentifier objectIdentifier = new ObjectIdentifier();
            objectIdentifier.parse(derSequence.getObjectAt(i).toASN1Primitive());
            if (this.pathLenConstraints == null) {
                this.pathLenConstraints = new ArrayList<ObjectIdentifier>();
            }
            this.pathLenConstraints.add(objectIdentifier);
        }
    }

}
