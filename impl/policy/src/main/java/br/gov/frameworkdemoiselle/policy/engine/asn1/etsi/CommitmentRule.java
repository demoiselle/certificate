package br.gov.frameworkdemoiselle.policy.engine.asn1.etsi;

import br.gov.frameworkdemoiselle.policy.engine.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

public class CommitmentRule extends CommonRules {

    private SelectedCommitmentTypes selCommitmentTypes;

    public SelectedCommitmentTypes getSelCommitmentTypes() {
        return selCommitmentTypes;
    }

    public void setSelCommitmentTypes(SelectedCommitmentTypes selCommitmentTypes) {
        this.selCommitmentTypes = selCommitmentTypes;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        super.parse(derObject);
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        this.selCommitmentTypes = new SelectedCommitmentTypes();
        this.selCommitmentTypes.parse(derSequence.getObjectAt(0).toASN1Primitive());
    }

}
