/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 * 
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 * 
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 * 
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 * 
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package br.gov.frameworkdemoiselle.certificate.ui.view;

import java.awt.Cursor;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.KeyStore;

import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.WindowConstants;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

import br.gov.frameworkdemoiselle.certificate.CertificateValidatorException;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.DriverNotAvailableException;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.InvalidPinException;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.KeyStoreLoader;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.KeyStoreLoaderException;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.PKCS11NotFoundException;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.factory.KeyStoreLoaderFactory;
import br.gov.frameworkdemoiselle.certificate.ui.action.FrameExecute;
import br.gov.frameworkdemoiselle.certificate.ui.config.FrameConfig;
import br.gov.frameworkdemoiselle.certificate.ui.factory.FrameExecuteFactory;
import br.gov.frameworkdemoiselle.certificate.ui.handler.PinCallbackHandler;
import br.gov.frameworkdemoiselle.certificate.ui.tiny.Item;

/**
 * @author SUPST/STDCS
*/
public class Principal extends javax.swing.JFrame {

	private static final long serialVersionUID = 1L;
	
	private JButton btnCancelar;
	private JButton btnExecutar;
	private JPanel panelbottom;
	private JPanel paneltop;
	private JScrollPane scrollPane;
	private JTable tableCertificates;
	
	KeyStore keystore = null;
	private boolean loaded = false;
	String alias = "";
	String className = "";
	CertificadoModel certificateModel;

	/**
	 * Creates new form NovoJFrame
	 */
	public Principal() {
		initComponents();
		className = System.getProperty("jnlp.myClassName");

		if (className == null || className.isEmpty()) {
			className = "br.gov.serpro.certificate.ui.user.App";
		}
		System.out.println("Utilizando implementacao da classe [" + className+ "]");

		while (keystore == null){
			keystore = this.getKeyStore();// Recupera o repositorio de certificados digitais
		}
		

		certificateModel = new CertificadoModel();
		certificateModel.populate(keystore);
		tableCertificates.setModel(certificateModel);

		if (tableCertificates.getRowCount() == 0) {
			btnExecutar.setEnabled(false);
		} else {
			tableCertificates.setRowSelectionInterval(0, 0);
		}

		alias = this.getAlias();

		tableCertificates.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

		// Dimensiona cada coluna separadamente
		TableColumn tableColumn1 = tableCertificates.getColumnModel().getColumn(0);
		tableColumn1.setPreferredWidth(200);

		TableColumn tableColumn2 = tableCertificates.getColumnModel().getColumn(1);
		tableColumn2.setPreferredWidth(140);

		TableColumn tableColumn3 = tableCertificates.getColumnModel().getColumn(2);
		tableColumn3.setPreferredWidth(140);

		TableColumn tableColumn4 = tableCertificates.getColumnModel().getColumn(3);
		tableColumn4.setPreferredWidth(300);

		this.setLocationRelativeTo(null); // Centraliza o frame
	}

	private void initComponents() {

		paneltop = new JPanel();
		scrollPane = new JScrollPane();
		tableCertificates = new JTable();
		panelbottom = new JPanel();
		btnExecutar = new JButton();
		btnCancelar = new JButton();

		setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		setLocation(new Point(0, 0));
		setResizable(false);
		setTitle(FrameConfig.LABEL_DIALOG_FRAME_TITLE.getValue());

		paneltop.setBorder(BorderFactory.createTitledBorder(
				BorderFactory.createEtchedBorder(),
				FrameConfig.CONFIG_DIALOG_TABLE_LABEL.getValue(),
				TitledBorder.DEFAULT_JUSTIFICATION,
				TitledBorder.DEFAULT_POSITION,
				new java.awt.Font(FrameConfig.CONFIG_DIALOG_TABLE_LABEL_FONT.getValue(), FrameConfig.CONFIG_DIALOG_TABLE_LABEL_FONT_STYLE.getValueInt(), FrameConfig.CONFIG_DIALOG_TABLE_LABEL_FONT_SIZE.getValueInt()))); // NOI18N

		scrollPane.setAutoscrolls(true);
		scrollPane.setViewportView(tableCertificates);

		tableCertificates.setBorder(BorderFactory.createEmptyBorder(1, 1, 1, 1));
		tableCertificates.setModel(new DefaultTableModel(
				new Object[][] { { null, null, null, null },
						{ null, null, null, null }, { null, null, null, null },
						{ null, null, null, null } }, new String[] { "Title 1",
						"Title 2", "Title 3", "Title 4" }));
		tableCertificates.setFillsViewportHeight(true);
		tableCertificates.setRowHeight(FrameConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_ROW_HEIGHT.getValueInt());

		GroupLayout paneltopLayout = new GroupLayout(paneltop);
		paneltop.setLayout(paneltopLayout);
		
		paneltopLayout.setHorizontalGroup(paneltopLayout.createParallelGroup(Alignment.LEADING)
				.addComponent(scrollPane, GroupLayout.DEFAULT_SIZE,	FrameConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_WIDTH.getValueInt(), Short.MAX_VALUE));
		
		paneltopLayout.setVerticalGroup(paneltopLayout.createParallelGroup(Alignment.LEADING)
				.addComponent(scrollPane,GroupLayout.PREFERRED_SIZE,FrameConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_HEIGHT.getValueInt(),GroupLayout.PREFERRED_SIZE));
	
		panelbottom.setBorder(BorderFactory.createEtchedBorder());

		btnExecutar.setText(FrameConfig.LABEL_DIALOG_BUTTON_RUN.getValue());
		btnExecutar.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				btnExecutarActionPerformed(evt);
			}
		});

		btnCancelar.setText(FrameConfig.LABEL_DIALOG_BUTTON_CANCEL.getValue());
		btnCancelar.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				btnCancelarActionPerformed(evt);
			}
		});
		
		GroupLayout panelbottomLayout = new GroupLayout(panelbottom);
		panelbottom.setLayout(panelbottomLayout);
		panelbottomLayout.setHorizontalGroup(panelbottomLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(panelbottomLayout.createSequentialGroup()
								.addComponent(btnExecutar,GroupLayout.PREFERRED_SIZE, FrameConfig.CONFIG_DIALOG_BUTTON_RUN_WIDTH.getValueInt(), GroupLayout.PREFERRED_SIZE)
								.addComponent(btnCancelar, GroupLayout.PREFERRED_SIZE, FrameConfig.CONFIG_DIALOG_BUTTON_CANCEL_WIDTH.getValueInt(), GroupLayout.PREFERRED_SIZE)
						));
		panelbottomLayout.setVerticalGroup(panelbottomLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(panelbottomLayout.createSequentialGroup()
								.addContainerGap()
								.addGroup(panelbottomLayout.createParallelGroup(Alignment.BASELINE)
										.addComponent(btnExecutar, GroupLayout.PREFERRED_SIZE, FrameConfig.CONFIG_DIALOG_BUTTON_RUN_HEIGHT.getValueInt(), GroupLayout.PREFERRED_SIZE)
										.addComponent(btnCancelar, GroupLayout.PREFERRED_SIZE, FrameConfig.CONFIG_DIALOG_BUTTON_CANCEL_HEIGHT.getValueInt(), GroupLayout.PREFERRED_SIZE)
								)
								.addContainerGap()
						));
	
		GroupLayout layout = new GroupLayout(getContentPane());
		getContentPane().setLayout(layout);
		layout.setHorizontalGroup(layout.createParallelGroup(Alignment.LEADING)
				.addGroup(layout.createSequentialGroup()
								.addContainerGap()
								.addGroup(layout.createParallelGroup(Alignment.LEADING,	false)
												.addComponent(paneltop, GroupLayout.DEFAULT_SIZE,GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
												.addComponent(panelbottom, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
								.addContainerGap(GroupLayout.DEFAULT_SIZE,Short.MAX_VALUE)));
		layout.setVerticalGroup(layout.createParallelGroup(Alignment.LEADING)
				.addGroup(layout.createSequentialGroup()
								.addContainerGap()
								.addComponent(paneltop, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addComponent(panelbottom, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
								.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

		pack();
	}

	private void btnExecutarActionPerformed(java.awt.event.ActionEvent evt) {
		FrameExecute frameExecute = FrameExecuteFactory.factory(className);
		frameExecute.execute(keystore, alias, this);

	}

	private void btnCancelarActionPerformed(java.awt.event.ActionEvent evt) {
		FrameExecute frameExecute = FrameExecuteFactory.factory(className);
		frameExecute.cancel(keystore, alias, this);
	}

	/**
	 * Retorna o keystore do dispositivo a partir do valor de pin
	 *
	 * @return
	 */
	public KeyStore getKeyStore() {
		try {
			Cursor hourGlassCursor = new Cursor(Cursor.WAIT_CURSOR);
			setCursor(hourGlassCursor);
			KeyStoreLoader loader = KeyStoreLoaderFactory
					.factoryKeyStoreLoader();
			loader.setCallbackHandler(new PinCallbackHandler());
			keystore = loader.getKeyStore();
			loaded = true;
			return keystore;

		} catch (DriverNotAvailableException e) {
			showFailDialog(FrameConfig.MESSAGE_ERROR_DRIVER_NOT_AVAILABLE
					.getValue());
		} catch (PKCS11NotFoundException e) {
			showFailDialog(FrameConfig.MESSAGE_ERROR_PKCS11_NOT_FOUND
					.getValue());
		} catch (CertificateValidatorException e) {
			showFailDialog(FrameConfig.MESSAGE_ERROR_LOAD_TOKEN.getValue());
		} catch (InvalidPinException e) {
			showFailDialog(FrameConfig.MESSAGE_ERROR_INVALID_PIN.getValue());
		} catch (KeyStoreLoaderException ke) {
			showFailDialog(ke.getMessage());
		} catch (Exception ex) {
			showFailDialog(FrameConfig.MESSAGE_ERROR_UNEXPECTED.getValue());
		} finally {
			Cursor hourGlassCursor = new Cursor(Cursor.DEFAULT_CURSOR);
			setCursor(hourGlassCursor);
		}
		return null;
	}

	/**
	 * Obtem o apelido associado a um certificado
	 *
	 * @return O apelido associado ao certificado
	 */
	public String getAlias() {
		if (tableCertificates.getModel().getRowCount() != 0) {
			int row = tableCertificates.getSelectedRow();
			Item item = (Item) tableCertificates.getModel().getValueAt(row, 0);
			return item.getAlias();
		} else {
			return "";
		}
	}

	/**
	 * Exibe as mensagens de erro
	 *
	 * @param message
	 */
	private void showFailDialog(String message) {
		JOptionPane.showMessageDialog(this, message,
				FrameConfig.LABEL_DIALOG_OPTION_PANE_TITLE.getValue(),
				JOptionPane.ERROR_MESSAGE);
	}
	
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Principal.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Principal.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Principal.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Principal.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Principal().setVisible(true);
            }
        });
    }
	
}
