import { EvaluationResults, PEJS, SelectResults, Validated } from '@sphereon/pe-js';
import { VerifiableCredential, VerifiablePresentation } from '@sphereon/pe-js/lib/verifiablePresentation/index';
import { PresentationDefinition, PresentationSubmission } from '@sphereon/pe-models';

export class PresentationExchangeAgent {
  // We update this if necessary
  pejs: PEJS = new PEJS();

  public evaluate(
    presentationDefinition: PresentationDefinition,
    verifiablePresentation: VerifiablePresentation
  ): EvaluationResults {
    this.pejs = new PEJS();
    return this.pejs.evaluate(presentationDefinition, verifiablePresentation);
  }

  public submissionFrom(
    presentationDefinition: PresentationDefinition,
    verifiableCredential: VerifiableCredential[]
  ): PresentationSubmission {
    return this.pejs.submissionFrom(presentationDefinition, verifiableCredential);
  }

  public selectFrom(
    presentationDefinition: PresentationDefinition,
    selectedCredentials: VerifiableCredential[],
    holderDid: string
  ): SelectResults {
    this.pejs = new PEJS();
    return this.pejs.selectFrom(presentationDefinition, selectedCredentials, holderDid);
  }

  public validatePresentationDefinition(presentationDefinition: PresentationDefinition): Validated {
    return this.pejs.validateDefinition(presentationDefinition);
  }

  public validatePresentationSubmission(presentationSubmission: PresentationSubmission): Validated {
    return this.pejs.validateSubmission(presentationSubmission);
  }
}
