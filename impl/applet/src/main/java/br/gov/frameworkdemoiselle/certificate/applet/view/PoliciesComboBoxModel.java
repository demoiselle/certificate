/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.certificate.applet.view;

import javax.swing.AbstractListModel;
import javax.swing.ComboBoxModel;

public class PoliciesComboBoxModel extends AbstractListModel implements ComboBoxModel {

    String[] Politicas = {
        "Política ICP-BRASIL com referência básica CMS, versão 1.0",
        "Política ICP-BRASIL com referência básica CMS, versão 1.1",
        "Política ICP-BRASIL com referência básica CMS, versão 2.0",
        "Política ICP-BRASIL com referência básica CMS, versão 2.1",
        "Política ICP-BRASIL com referência do tempo CMS, versão 1.0",
        "Política ICP-BRASIL com referência do tempo CMS, versão 1.1",
        "Política ICP-BRASIL com referência do tempo CMS, versão 2.0",
        "Política ICP-BRASIL com referência do tempo CMS, versão 2.1"
    };

    String selection = null;

    @Override
    public Object getElementAt(int index) {
        return Politicas[index];
    }

    @Override
    public int getSize() {
        return Politicas.length;
    }

    @Override
    public void setSelectedItem(Object anItem) {
        selection = (String) anItem; // to select and register an
    } // item from the pull-down list

    // Methods implemented from the interface ComboBoxModel
    @Override
    public Object getSelectedItem() {
        return selection; // to add the selection to the combo box
    }

}
