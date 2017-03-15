//
//  ListViewController.swift
//  swiftddp
//
//  Created by Michael Arthur on 13/08/14.
//  Copyright (c) 2014. All rights reserved.
//

import Foundation
import UIKit

class ListViewController: UIViewController, UITableViewDataSource, UITableViewDelegate {
    
    @IBOutlet weak var tableview: UITableView!
    var meteor:MeteorClient!
    var lists:M13MutableOrderedDictionary!
    var userId:String?
    
    required init(coder aDecoder: NSCoder) {
        fatalError("NSCoding not supported")
    }
    
    init(nibName nibNameOrNil: String!, bundle nibBundleOrNil: NSBundle!, meteor: MeteorClient!) {
        
        super.init(nibName: nibNameOrNil, bundle: nibBundleOrNil)
        self.meteor = meteor
        self.lists = self.meteor.collections["lists"] as M13MutableOrderedDictionary
        
    }
    
    
    
    
    override func viewWillAppear(animated: Bool) {
        self.meteor.addObserver(self, forKeyPath: "websocketReady", options: NSKeyValueObservingOptions.New, context: nil)
        self.navigationItem.title = "My Lists"
        self.navigationController?.navigationBarHidden = false
        self.navigationItem.hidesBackButton = true
        
        var logoutButton:UIBarButtonItem = UIBarButtonItem(title: "Logout", style: UIBarButtonItemStyle.Plain, target: self, action: "logout")
        
        self.navigationItem.rightBarButtonItem = logoutButton
        
        NSNotificationCenter.defaultCenter().addObserver(self, selector: "didReceiveUpdate:", name: "lists_added", object: nil)
        NSNotificationCenter.defaultCenter().addObserver(self, selector: "didReceiveUpdate:", name: "lists_removed", object: nil)
        
        
    }
    
    func didReceiveUpdate(notification:NSNotification) {
        self.tableview.reloadData()
    }
    
    func logout() {
        self.meteor.logout()
        self.navigationController?.popToRootViewControllerAnimated(true)
    }
    
    func tableView(tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return Int(self.lists.count())
    }
    
    override func observeValueForKeyPath(keyPath: String, ofObject object: AnyObject!, change: [NSObject : AnyObject]!, context: UnsafeMutablePointer<()>) {
        
        if (keyPath == "websocketReady" && meteor.websocketReady) {
            
        }
    }
    
    
    
    var selectedList:[String:String]!
    
    
    
    
    func tableView(tableView: UITableView, cellForRowAtIndexPath indexPath: NSIndexPath) -> UITableViewCell {
        var cellIdentifier = "list"
        var cell:UITableViewCell
        
        if var tmpCell: AnyObject = tableView.dequeueReusableCellWithIdentifier(cellIdentifier) {
            cell = tmpCell as UITableViewCell
        } else {
            cell = UITableViewCell(style: UITableViewCellStyle.Default, reuseIdentifier: cellIdentifier) as UITableViewCell
        }
        
        
        selectedList  = self.lists.objectAtIndex(UInt(indexPath.row)) as? [String:String]
        cell.textLabel?.text = selectedList["name"]
        
        var shareButton:UIButton = UIButton.buttonWithType(UIButtonType.Custom) as UIButton
        
        shareButton.frame = CGRectMake(255.0, 5.0, 55.0, 34.0)
        shareButton.backgroundColor = UIColor.greenColor()
        shareButton.setTitle("Share", forState: UIControlState.Normal)
        shareButton.addTarget(self, action: "didClickShareButton:forEvent:", forControlEvents: .TouchUpInside)
        
        cell.addSubview(shareButton)
        
        
        return cell
    }
    
    var shareWithTF:UITextField!
    
    func didClickShareButton(sender:AnyObject!,forEvent event:UIEvent!) {
        var touch:UITouch = event.allTouches()!.anyObject() as UITouch
        var location:CGPoint = touch.locationInView(self.view)
        
        var view:UIView = UIView(frame: CGRectMake(0.0, location.y, 320.0, 100.0))
        view.backgroundColor = UIColor.whiteColor()
        var shareWithTextField:UITextField = UITextField(frame: CGRectMake(10.0, 50.0, 240.0, 44.0))
        shareWithTF = shareWithTextField
        shareWithTextField.borderStyle = UITextBorderStyle.Line
        var button:UIButton = UIButton.buttonWithType(UIButtonType.Custom) as UIButton
        button.frame = CGRectMake(255.0, 50.0, 60.0, 44.0)
        button.backgroundColor = UIColor.greenColor()
        button.setTitle("Send", forState: UIControlState.Normal)
        button.addTarget(self, action: "didClickShareWithButton", forControlEvents: .TouchUpInside)
        view .addSubview(shareWithTextField)
        view .addSubview(button)
        
        var modalBackground:UIView = UIView(frame: self.view.frame)
        modalBackground.backgroundColor = UIColor.blackColor()
        modalBackground.alpha = 0.7
        
        self.view .addSubview(modalBackground)
        self.view .addSubview(view)
        
    }
    
    func didClickShareWithButton(sender: AnyObject!) {
        var id = selectedList["_id"] as String!
        var parameters = [["_id":id], ["set": ["share_with":shareWithTF.text]]] //This has to be an NSArray
        self.meteor.callMethodName("/lists/update", parameters: parameters)
        self.view.subviews.last?.removeFromSuperview()
        self.view.subviews.last?.removeFromSuperview()
        
    }
    
    func tableView(tableView: UITableView!, canEditRowAtIndexPath indexPath: NSIndexPath!) -> Bool {
        return true
    }
    
    func tableView(tableView: UITableView!, commitEditingStyle editingStyle: UITableViewCellEditingStyle, forRowAtIndexPath indexPath: NSIndexPath!) {
        var list = self.lists.objectAtIndex(UInt(indexPath.row)) as [String:AnyObject]
        var id = list["_id"] as String
        self.meteor.callMethodName("/lists/remove", parameters: [["_id":id]])
    }
    
    func tableView(tableView: UITableView!, didSelectRowAtIndexPath indexPath: NSIndexPath!) {
        var list = self.lists.objectAtIndex(UInt(indexPath.row)) as [String:AnyObject]
        var viewController:ViewController = ViewController(nibNameOrNil: "ViewController", bundle: nil, meteor: self.meteor, listName: list["name"] as String)
        
        viewController.userId = self.userId
        self.navigationController?.pushViewController(viewController, animated: true)
    }
    
    
    
    
}