//
//  ViewController.swift
//  swiftddp
//
//  Created by Michael Arthur on 7/6/14.
//  Copyright (c) 2014. All rights reserved.
//

import UIKit

class ViewController: UIViewController,UITableViewDataSource, AddViewControllerDelegate {
    
    var meteor:MeteorClient!
    var listName:NSString!
    var userId:NSString!
    
    @IBOutlet weak var tableview: UITableView!
    
    required init(coder aDecoder: NSCoder) {
        super.init()
        
        
    }
    
    override init(nibName nibNameOrNil: String!, bundle nibBundleOrNil: NSBundle!) {
        
        super.init(nibName: nibNameOrNil, bundle: nibBundleOrNil)
        
    }
    
    init(nibNameOrNil: String!, bundle nibBundleOrNil: NSBundle!, meteor: MeteorClient!, listName:NSString!) {
        
        super.init(nibName: nibNameOrNil, bundle: nibBundleOrNil)
        // if(self != nil) {
        self.meteor = meteor
        self.listName = listName
        //}
    }
    
    override func viewWillAppear(animated: Bool) {
        self.navigationItem.title = self.listName
        var addButton:UIBarButtonItem = UIBarButtonItem(barButtonSystemItem: UIBarButtonSystemItem.Add, target: self, action: "didTouchAdd:")
        
        self.navigationItem.setRightBarButtonItem(addButton, animated: true)

        NSNotificationCenter.defaultCenter().addObserver(self, selector: "didReceiveUpdate:", name: "things_added", object: nil)
        NSNotificationCenter.defaultCenter().addObserver(self, selector: "didReceiveUpdate:", name: "things_changed", object: nil)
        NSNotificationCenter.defaultCenter().addObserver(self, selector: "didReceiveUpdate:", name: "things_removed", object: nil)
    }
    
    override func viewWillDisappear(animated: Bool) {
        NSNotificationCenter.defaultCenter().removeObserver(self)
    }
    
    
    func didReceiveUpdate(notification:NSNotification) {
        self.tableview.reloadData()
    }
    
    func computedList() -> NSArray {
        
        
        var pred:NSPredicate = NSPredicate(format: "(listName like %@)", self.listName)!
        let temp = self.meteor.collections["things"] as M13MutableOrderedDictionary
        let temp2 = temp.allObjects() as NSArray
        return temp2.filteredArrayUsingPredicate(pred)
        
        
    }
    
    @IBAction func didTouchAdd(sender: AnyObject) {
        var addController = AddViewController(nibName: "AddViewController", bundle: nil)
        
        addController.delegate = self
        self.presentViewController(addController, animated: true, completion: nil)
    }
    
    func tableView(tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        if(self.meteor.collections["things"] != nil){
            
            return self.computedList().count
        }
        return 0
    }
    
    func tableView(tableView: UITableView, cellForRowAtIndexPath indexPath: NSIndexPath) -> UITableViewCell {
        let cellIdentifier:NSString! = "thing"
        var cell:UITableViewCell
        
        if var tmpCell: AnyObject = tableView.dequeueReusableCellWithIdentifier(cellIdentifier) {
            cell = tmpCell as UITableViewCell
        } else {
            cell = UITableViewCell(style: UITableViewCellStyle.Default, reuseIdentifier: cellIdentifier) as UITableViewCell
        }
        
        if(self.meteor.collections["things"] != nil){
            var thing:NSDictionary = self.computedList()[indexPath.row] as NSDictionary
            cell.textLabel?.text = thing["msg"] as String
            return cell
        }
        cell.textLabel?.text = "dummy"
        return cell
        
    }
    
    func tableView(tableView: UITableView, canEditRowAtIndexPath indexPath: NSIndexPath) -> Bool {
        return true
    }
    
    func tableView(tableView: UITableView, commitEditingStyle editingStyle: UITableViewCellEditingStyle, forRowAtIndexPath indexPath: NSIndexPath) {
        if(editingStyle == UITableViewCellEditingStyle.Delete) {
            //If statement prevents crash
            if(self.meteor.collections["things"] != nil){
                var thing:NSDictionary = self.computedList()[indexPath.row] as NSDictionary
                let thingy = thing["_id"] as NSString
                self.meteor.callMethodName("/things/remove", parameters: [["_id":thingy]])
            }
        }
    }
    
    func didAddThing(message: NSString!) {
        self.dismissViewControllerAnimated(true, completion: nil)
        var parameters:NSArray = [["_id": NSUUID().UUIDString,
            "msg":message,
            "owner":self.userId,
            "listName":self.listName]]
        
        self.meteor.callMethodName("/things/insert", parameters: parameters)
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        
        
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    
}

